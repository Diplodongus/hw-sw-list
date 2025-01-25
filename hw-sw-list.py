#!/usr/bin/env python3

import argparse
import ipaddress
import logging
import sys
import time
import csv
from datetime import datetime
from getpass import getpass
import subprocess
import paramiko
import re
from typing import List, Dict, Tuple, Optional

class NetworkInventory:
    def __init__(self, username: str, password: str, subnet: str, debug: bool = False, quiet: bool = False):
        """Initialize NetworkInventory with credentials and configuration."""
        self.username = username
        self.password = str(password) if password is not None else ""
        
        # Handle both single IP and subnet inputs
        try:
            # First try to create an IP network
            self.subnet = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            try:
                # If that fails, try to create a single IP network
                single_ip = ipaddress.ip_address(subnet)
                # Create a /32 network for single IP
                self.subnet = ipaddress.ip_network(f"{single_ip}/32", strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid IP address or subnet format: {subnet}") from e
        
        # Set up logging
        self.setup_logging(debug, quiet)
        
    def setup_logging(self, debug: bool, quiet: bool) -> None:
        """Configure logging with detailed formatting for debugging."""
        self.logger = logging.getLogger('NetworkInventory')
        self.logger.setLevel(logging.DEBUG if debug else logging.INFO)
        
        if not quiet:
            console_handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s')
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

    def ping_sweep(self) -> Tuple[List[str], List[str]]:
        """Perform ping sweep of the subnet."""
        reachable = []
        unreachable = []
        
        self.logger.info(f"Starting ping sweep of subnet {self.subnet}")
        
        # Determine which subprocess.run parameters to use based on Python version
        if sys.version_info >= (3, 7):
            subprocess_text_param = {'text': True}
        else:
            subprocess_text_param = {'universal_newlines': True}
        
        # For single IP (subnet with /32), we only need to check one address
        hosts = [self.subnet.network_address] if self.subnet.prefixlen == 32 else self.subnet.hosts()
        
        for ip in hosts:
            ip_str = str(ip)
            self.logger.debug(f"Pinging {ip_str}")
            
            try:
                # Determine OS-specific ping command
                if sys.platform.startswith('win'):
                    cmd = ['ping', '-n', '1', '-w', '1000', ip_str]
                else:
                    # Linux/Unix ping with more verbose output
                    cmd = ['ping', '-c', '1', '-W', '1', ip_str]
                
                self.logger.debug(f"Running command: {' '.join(cmd)}")
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    **subprocess_text_param
                )
                
                # Log complete output regardless of result
                self.logger.debug(f"Ping return code: {result.returncode}")
                if result.stdout:
                    self.logger.debug(f"Ping stdout:\n{result.stdout}")
                if result.stderr:
                    self.logger.debug(f"Ping stderr:\n{result.stderr}")
                
                if result.returncode == 0:
                    self.logger.debug(f"{ip_str} is reachable")
                    reachable.append(ip_str)
                else:
                    self.logger.debug(f"{ip_str} is unreachable (Return code: {result.returncode})")
                    unreachable.append(ip_str)
                    
            except subprocess.SubprocessError as e:
                self.logger.error(f"Error executing ping for {ip_str}: {str(e)}")
                self.logger.debug("Exception details:", exc_info=True)
                unreachable.append(ip_str)
            except Exception as e:
                self.logger.error(f"Unexpected error pinging {ip_str}: {str(e)}")
                self.logger.debug("Exception details:", exc_info=True)
                unreachable.append(ip_str)
                
        self.logger.info(f"Ping sweep complete. Found {len(reachable)} reachable hosts")
        if reachable:
            self.logger.debug(f"Reachable hosts: {reachable}")
        return reachable, unreachable

    def read_until_pattern(self, shell, pattern: str, timeout: int = 30) -> str:
        """
        Read from shell until pattern is found or timeout occurs.
        Handles --More-- prompts automatically.
        """
        buffer = ""
        start_time = time.time()
        
        while True:
            if time.time() - start_time > timeout:
                self.logger.warning(f"Timeout waiting for pattern: {pattern}")
                break
                
            if shell.recv_ready():
                chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                self.logger.debug(f"Received chunk: {chunk}")
                buffer += chunk
                
                # Handle --More-- prompt
                if re.search(r'--More--|^\s*--More\s*$', buffer, re.MULTILINE):
                    self.logger.debug("Handling --More-- prompt")
                    shell.send(' ')
                    time.sleep(0.5)
                    continue
                
                # Check if we've found our pattern
                if re.search(pattern, buffer):
                    break
            else:
                time.sleep(0.1)
        
        return buffer

    def execute_command(self, shell, command: str) -> str:
        """
        Execute a single command and return its output.
        Handles command sending and output collection with proper timing.
        """
        self.logger.debug(f"Executing command: {command}")
        
        # Clear any pending data
        while shell.recv_ready():
            shell.recv(4096)
        
        # Send command with proper line ending
        shell.send(command + '\r\n')
        time.sleep(1)  # Wait for command to be processed
        
        # Read until we see a prompt
        output = self.read_until_pattern(shell, r'\S+[#>]\s*$')
        self.logger.debug(f"Complete output:\n{output}")
        
        return output

    def get_device_info(self, ip: str) -> Optional[Dict]:
        """
        SSH into device and gather required information.
        Uses a single SSH session for all commands.
        """
        ssh = None
        shell = None
        device_info = {}
        
        try:
            # Initialize SSH connection
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            self.logger.debug(f"Connecting to {ip}")
            ssh.connect(
                ip,
                username=self.username,
                password=self.password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )
            
            # Create interactive shell with generous size
            shell = ssh.invoke_shell(width=200, height=1000)
            shell.settimeout(30)
            
            # Wait for initial prompt
            initial_output = self.read_until_pattern(shell, r'\S+[#>]\s*$')
            self.logger.debug(f"Initial prompt received:\n{initial_output}")
            
            # Execute commands and gather information
            commands = [
                "show version",
                "show inventory",
                "dir flash:"  # Removed the pipe since some IOS versions don't support it
            ]
            
            for command in commands:
                output = self.execute_command(shell, command)
                
                if command == "show version":
                    # Extract hostname
                    hostname_match = re.search(r"(\S+)#", output)
                    if hostname_match:
                        device_info['hostname'] = hostname_match.group(1)
                    
                    # Extract software version
                    version_match = re.search(r"Cisco IOS Software.*Version ([^,]+)", output)
                    if version_match:
                        device_info['system_description'] = version_match.group(0)
                    
                    # Extract serial number
                    serial_match = re.search(r"System serial number\s*:\s*(\S+)", output)
                    if serial_match:
                        device_info['serial_number'] = serial_match.group(1)
                
                elif command == "show inventory":
                    # Extract chassis type
                    chassis_match = re.search(r"PID: (\S+)", output)
                    if chassis_match:
                        device_info['chassis_vendor_type'] = chassis_match.group(1)
                
                elif command == "dir flash:":
                    # Look for different possible flash size patterns
                    flash_patterns = [
                        r"(\d+) bytes total",  # Standard format
                        r"(\d+) bytes used",   # Alternative format
                        r"(\d+) bytes free"    # Another possibility
                    ]
                    
                    for pattern in flash_patterns:
                        flash_match = re.search(pattern, output)
                        if flash_match:
                            try:
                                flash_bytes = int(flash_match.group(1))
                                flash_mb = flash_bytes / (1024 * 1024)
                                device_info['flash_size_mb'] = f"{flash_mb:.2f}"
                                break
                            except (ValueError, IndexError) as e:
                                self.logger.debug(f"Error processing flash size: {e}")
                                continue
                    
                    if 'flash_size_mb' not in device_info:
                        self.logger.debug(f"Could not determine flash size from output: {output}")
            
            device_info['ip_address'] = ip
            return device_info
            
        except paramiko.AuthenticationException:
            self.logger.error(f"Authentication failed for {ip}")
            return None
        except paramiko.SSHException as e:
            self.logger.error(f"SSH error for {ip}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error for {ip}: {str(e)}")
            self.logger.debug("Exception details:", exc_info=True)
            return None
        finally:
            if shell:
                try:
                    shell.close()
                except:
                    pass
            if ssh:
                try:
                    ssh.close()
                except:
                    pass

    def export_to_csv(self, devices: List[Dict]) -> str:
        """Export device information to CSV file with timestamp."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"network_inventory_{timestamp}.csv"
        
        fields = [
            'hostname',
            'ip_address',
            'system_description',
            'serial_number',
            'chassis_vendor_type',
            'flash_size_mb'
        ]
        
        try:
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fields)
                writer.writeheader()
                for device in devices:
                    writer.writerow(device)
            
            self.logger.info(f"Inventory exported to {filename}")
            return filename
        except Exception as e:
            self.logger.error(f"Error exporting to CSV: {e}")
            return ""

def main():
    """Main entry point with argument parsing and error handling."""
    parser = argparse.ArgumentParser(description='Network Device Inventory Tool')
    parser.add_argument('subnet', help='Network subnet in CIDR notation (e.g., 10.0.0.0/24)')
    parser.add_argument('-u', '--username', help='TNA username')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode - output only to CSV')
    args = parser.parse_args()

    # Get credentials
    username = args.username or input("Enter TNA username: ")
    password = getpass("Enter password: ")

    try:
        # Initialize inventory object
        inventory = NetworkInventory(username, password, args.subnet, args.debug, args.quiet)
        
        # Perform ping sweep
        reachable, unreachable = inventory.ping_sweep()
        
        # Gather device information
        devices = []
        for ip in reachable:
            device_info = inventory.get_device_info(ip)
            if device_info:
                devices.append(device_info)
            else:
                response = input(f"Failed to gather information from {ip}. Continue? (y/n): ")
                if response.lower() != 'y':
                    break
        
        # Export results
        if devices:
            inventory.export_to_csv(devices)
        else:
            inventory.logger.error("No device information collected")
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()