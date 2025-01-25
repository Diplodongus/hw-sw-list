# Network Device Inventory Tool

## Description

A Python script for network administrators to automate Cisco device discovery and inventory collection. It performs subnet scanning and securely retrieves detailed hardware/software information via SSH.

## Core Functionality

- **Network Discovery:** Performs ping sweep of IPv4 subnets or single IPs
- **Secure Access:** Uses SSH with keyboard-interactive authentication
- **Data Collection:** Executes Cisco IOS commands to gather:
     - Device hostname and IP
     - IOS version details
     - Serial numbers
     - Hardware model information
     - Available flash memory
- **Output Management:**
     - CSV export with timestamps
     - Configurable logging levels
     - Progress tracking
     - Error handling

## Installation

### Prerequisites

- Python 3.6+
- Required packages:
          - `paramiko` for SSH
          - Standard library modules

### Setup

1. **Clone Repository**

           ```bash
           git clone https://github.com/yourusername/network-inventory-tool.git
           cd network-inventory-tool
           ```

2. **Install Dependencies**

           ```bash
           pip install -r requirements.txt
           ```

## Usage

```bash
python hw-sw-list.py <subnet> [options]
```

### Arguments

- `<subnet>`: Target network (e.g., `10.0.0.0/24` or single IP)

### Options

- `-u`, `--username`: TNA authentication username
- `-d`, `--debug`: Enable detailed logging
- `-q`, `--quiet`: CSV-only output mode

### Example

```bash
python hw-sw-list.py 192.168.1.0/24 -u admin -d
```

## Output Format

Generates `network_inventory_<timestamp>.csv` with:

- Device hostname
- IP address
- IOS version
- Serial number
- Hardware model
- Flash memory size

## Error Handling

- Graceful handling of unreachable hosts
- Authentication failure recovery
- Timeout management
- FIPS compliance support

## Contributing

Submit issues or pull requests for improvements.

## License

[MIT License](LICENSE)
```