```markdown
# Network Device Inventory Tool

## Description

A Python script designed to perform a comprehensive network inventory by ping sweeping a specified subnet and gathering detailed device information via SSH.

## Features

- **Ping Sweep:** Identifies reachable and unreachable hosts within a given subnet.
- **SSH Data Collection:** Gathers device information such as hostname, software version, serial number, chassis type, and flash size.
- **CSV Export:** Exports the collected data to a timestamped CSV file for easy analysis.
- **Logging:** Supports debug and quiet modes for flexible logging preferences.

## Installation

### Prerequisites

- Python 3.6 or higher
- Required Python packages:
    - `paramiko`
    - `argparse`
    - Additional standard libraries as used in the script.

### Setup

1. **Clone the Repository**

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

- `<subnet>`: Network subnet in CIDR notation (e.g., `10.0.0.0/24`)

### Options

- `-u`, `--username`: Specify the TNA username.
- `-d`, `--debug`: Enable debug logging for detailed output.
- `-q`, `--quiet`: Activate quiet mode to suppress console output and log only to CSV.

### Example

```bash
python hw-sw-list.py 192.168.1.0/24 -u admin -d
```

## Output

The script generates a CSV file named `network_inventory_<timestamp>.csv` containing the following fields:

- `hostname`
- `ip_address`
- `system_description`
- `serial_number`
- `chassis_vendor_type`
- `flash_size_mb`

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License

This project is licensed under the [MIT License](LICENSE).
```