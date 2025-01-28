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
            
            def handler(title, instructions, prompt_list):
                """Handle keyboard-interactive authentication"""
                self.logger.debug(f"Keyboard-interactive auth - Title: {title}, Instructions: {instructions}")
                answers = []
                for prompt in prompt_list:
                    self.logger.debug(f"Prompt: {prompt[0]}")
                    if 'password' in prompt[0].lower():
                        answers.append(self.password)
                    else:
                        answers.append(self.username)
                return answers
            
            self.logger.debug(f"Connecting to {ip}")
            try:
                # Connect with keyboard-interactive authentication
                connect_params = {
                    'hostname': ip,
                    'username': self.username,
                    'timeout': 10,
                    'allow_agent': False,
                    'look_for_keys': False,
                    'auth_timeout': 20,
                    'auth_method': 'keyboard-interactive'
                }
                
                transport = paramiko.Transport((ip, 22))
                transport.connect()
                transport.auth_interactive(self.username, handler)
                ssh._transport = transport
                
            except Exception as e:
                if "digital envelope routines" in str(e) or "EVP_DigestInit_ex" in str(e):
                    self.logger.debug("FIPS-related error detected, retrying with modified transport configuration")
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    # Create transport with disabled algorithms
                    transport = paramiko.Transport((ip, 22))
                    transport.disabled_algorithms = {
                        'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']
                    }
                    
                    # Start transport and attempt keyboard-interactive auth
                    transport.connect()
                    transport.auth_interactive(self.username, handler)
                    ssh._transport = transport
                else:
                    raise
            
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
                "dir flash:"
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
                    
                    # Detect if this is a stack by looking for multiple System Serial Numbers
                    sys_serials = list(re.finditer(r"System Serial Number\s*:\s*(\S+)", output))

                    if len(sys_serials) > 1:
                        # This is a stack - create entries for each member
                        device_info['stack_members'] = []
                        for serial in sys_serials:
                            device_info['stack_members'].append({
                                'serial_number': serial.group(1),
                                'chassis_vendor_type': None  # Will be populated from show inventory
                            })
                    else:
                        # Single device - try system serial number first, then other serials
                        if sys_serials:
                            device_info['serial_number'] = sys_serials[0].group(1)
                        else:
                            serial_match = re.search(r"System serial number\s*:\s*(\S+)", output)
                            if serial_match:
                                device_info['serial_number'] = serial_match.group(1)
                
                elif command == "show inventory":
                    # Extract and process chassis information from show inventory
                    chassis_entries = list(re.finditer(r"NAME: \"([^\"]+)\".*?\nPID: (\S+)", output, re.DOTALL))
                    chassis_types = []

                    # First, find a valid base chassis model to use as our pattern
                    base_model = None
                    for entry in chassis_entries:
                        pid = entry.group(2)
                        # Look for standard Cisco switch model patterns (WS-C, C9, etc.)
                        if re.match(r'(WS-C|C\d{1})', pid):
                            base_model = pid.split('-')[0]  # Extract the base model prefix
                            chassis_types.append(pid)
                            self.logger.debug(f"Found base model: {base_model} from PID: {pid}")
                            break

                    # If we found a valid base model, use it to find other matching chassis
                    if base_model:
                        matching_chassis = [
                            entry.group(2) for entry in chassis_entries[1:]
                            if entry.group(2).startswith(base_model)
                        ]
                        chassis_types.extend(matching_chassis)
                        self.logger.debug(f"Found {len(chassis_types)} total chassis: {chassis_types}")
                    else:
                        self.logger.warning(f"No valid chassis model pattern found in inventory")

                    # Now assign the chassis types to the appropriate devices
                    if 'stack_members' in device_info:
                        # For stacked devices, match chassis types with stack members
                        for i, chassis in enumerate(chassis_types):
                            if i < len(device_info['stack_members']):
                                device_info['stack_members'][i]['chassis_vendor_type'] = chassis
                    else:
                        # For single device, use the first chassis type found
                        if chassis_types:
                            device_info['chassis_vendor_type'] = chassis_types[0]
                
                elif command == "dir flash:":
                    # Look for different possible flash size patterns
                    flash_patterns = [
                        r"(\d+) bytes total",
                        r"(\d+) bytes used",
                        r"(\d+) bytes free"
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
        timestamp = datetime.now().strftime("%Y-%m-%d, %H:%M:%S %Z")
        filename = f"network_inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        # Define categories and their corresponding fields
        categories = [
            "Cisco Interfaces and Modules",
            "Routers",
            "Switches and Hubs",
            "Storage Networking",
            "Voice and Telephony",
            "Wireless Controllers",
            "Access Points",
            "Security and VPN",
            "Optical Transport"
        ]

        fields = [
            'Hostname',
            'IP Address',
            'System Description',
            'Serial Number',
            'Chassis Vendor Type',
            'Total Flash Device Size (MB)'
        ]
        
        try:
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                
                # Write report header
                writer.writerow(['Report Title: Device inventory'])
                writer.writerow([f'Generated: {timestamp}'])
                writer.writerow([])
                writer.writerow([])

                # Process each category
                for category in categories:
                    writer.writerow([f'Category: {category}'])
                    
                    # For now, assume all devices are switches. Want to add logic to categorize devices
                    if category == "Switches and Hubs" and devices:
                        writer.writerow(fields)
                        writer.writerow([])  # Empty row after header
                        
                        for device in devices:
                            if 'stack_members' in device:
                                # Handle stacked devices
                                base_info = [
                                    device.get('hostname', ''),
                                    device.get('ip_address', ''),
                                    device.get('system_description', ''),
                                    '',  # Serial number will come from stack member
                                    '',  # Chassis type will come from stack member
                                    device.get('flash_size_mb', '')
                                ]
                                for member in device['stack_members']:
                                    row = base_info.copy()
                                    row[3] = member.get('serial_number', '')
                                    row[4] = member.get('chassis_vendor_type', '')
                                    writer.writerow(row)
                            else:
                                # Handle single device
                                writer.writerow([
                                    device.get('hostname', ''),
                                    device.get('ip_address', ''),
                                    device.get('system_description', ''),
                                    device.get('serial_number', ''),
                                    device.get('chassis_vendor_type', ''),
                                    device.get('flash_size_mb', '')
                                ])
                    else:
                        writer.writerow(['None.'])
                    
                    writer.writerow([' '])  # Space between categories
            
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