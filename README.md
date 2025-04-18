# PortLinker

![MIT License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Built with PySide6](https://img.shields.io/badge/built%20with-PySide6-ff69b4)

A powerful port forwarding utility for Windows that simplifies redirecting network traffic between interfaces, particularly useful for WSL (Windows Subsystem for Linux) connectivity.

![PortLinker Screenshot](assets/Port.png)

## Overview

PortLinker is a Windows application that makes it easy to set up port forwarding rules between different network interfaces or IP addresses. It provides a user-friendly interface to create, manage, and monitor port forwarding configurations without having to use complex command-line operations.

## Features

- **Simple Port Forwarding**: Forward ports from your Windows machine to other IP addresses
- **Multi-Port Support**: Forward multiple ports at once using various selection formats:
  - Individual ports (e.g., `80`)
  - Comma-separated lists (e.g., `80, 443, 8080`)
  - Port ranges (e.g., `8000-8010`)
  - Default set of common ports (`all` = 80, 443, 9072)
- **Automatic IP Detection**: Easily find your machine's IP address with one click
- **Windows Firewall Integration**: Automatically create necessary firewall rules
- **Conflict Resolution**: Detect and resolve port conflicts with running services
- **User-friendly UI**: Clean, modern interface with clear status indicators
- **Troubleshooting Tools**: Built-in network diagnostics and connection testing

## Requirements

- Windows 10 or later
- Administrator privileges (required to modify network configuration)
- Python 3.8+ with PySide6 installed (or use the standalone executable)

## Installation

### Pre-built Executable

1. Download the latest release from the [Releases](https://github.com/JodyPutra-dev/PYTHON_PORT_LINKER/releases) page
2. Extract the ZIP file to any location on your computer
3. Run `PortLinker.exe` (the application will request administrator privileges)

### Running from Source

If you prefer to run from source code:

1. Clone the repository:
   ```
   git clone https://github.com/JodyPutra-dev/PYTHON_PORT_LINKER.git
   cd PYTHON_PORT_LINKER
   ```

2. Install dependencies:
   ```
   pip install PySide6
   ```

3. Run the application with administrator privileges:
   ```
   python PortLinker.py
   ```

   Note: The application requires administrator privileges to modify network settings. If running from a terminal, make sure to run your terminal as administrator.

### Building from Source

To build the executable yourself:

1. Install PyInstaller:
   ```
   pip install pyinstaller
   ```

2. Build the executable:
   ```
   pyinstaller --onefile --icon=icon.ico --version-file=version.txt PortLinker.py
   ```

3. Find the executable in the `dist` folder

## Usage

### Basic Port Forwarding

1. **Select IP Addresses**:
   - **Listen IP**: The IP address of your Windows machine (usually detected automatically)
   - **Target IP**: The destination IP address where traffic should be forwarded (e.g., WSL IP)

2. **Select Ports**:
   - Type `all` to use default ports (80, 443, 9072)
   - Enter specific ports separated by commas
   - Use a range format for consecutive ports (e.g., `8000-8010`)

3. **Enable Port Forwarding**:
   - Click "Aktifkan Port Forwarding"
   - The application will create necessary network and firewall rules
   - Status will be updated with the active configuration

### Common Use Cases

#### Forwarding to WSL

To access services running in WSL from other devices on your network:
1. Set "Listen IP" to your Windows machine's network IP
2. Set "Target IP" to your WSL instance's IP (typically `172.x.x.x`)
3. Select the ports you want to forward
4. Click "Aktifkan Port Forwarding"

#### Accessing Local Services Remotely

To make locally running services available on your network:
1. Set "Listen IP" to your Windows machine's network IP
2. Set "Target IP" to `127.0.0.1`
3. Select the ports your services are running on
4. Click "Aktifkan Port Forwarding"

## Troubleshooting

PortLinker includes a dedicated troubleshooting tab with:
- Network configuration information
- Active port status
- Firewall rule verification
- Common connection issues and solutions

For connection problems:
1. Ensure devices are on the same network
2. Check Windows Firewall settings
3. Verify the correct IP addresses are being used
4. Confirm target services are running and accessible

## How It Works

PortLinker uses Windows' built-in `netsh interface portproxy` commands to create port forwarding rules at the system level. It also manages Windows Firewall rules to ensure forwarded ports are accessible.

## License

This software is provided as-is under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Credits

Developed by Muhammad Jody Putra Islami alias Exp9072
 
