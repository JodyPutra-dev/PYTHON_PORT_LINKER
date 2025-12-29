# PortLinker

![MIT License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Built with PySide6](https://img.shields.io/badge/built%20with-PySide6-ff69b4)

A port forwarding utility for Windows that simplifies redirecting network traffic between interfaces, particularly useful for WSL (Windows Subsystem for Linux) connectivity.

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
- **Cloudflare Tunnel Integration**: Expose local services to the internet securely using Cloudflare's tunnel technology

## ⚠️ Antivirus Warning

**Important:** Some antivirus software may flag PortLinker as suspicious or as a false positive. This is common for network utilities that need administrative privileges and modify system network settings.

### Why This Happens:
- PortLinker requires administrator privileges to modify Windows network settings
- The application uses Windows `netsh` commands to configure port forwarding
- It creates Windows Firewall rules to allow traffic through forwarded ports
- PyInstaller-packaged executables are sometimes flagged by antivirus software

### What To Do:
1. **Add an exception** in your antivirus software for the PortLinker executable
2. **Use the source code** version instead of the pre-built executable if you prefer
3. **Verify the download** came from the official GitHub repository
4. **Build from source** yourself if you want complete assurance

PortLinker is a completely safe and open-source application. It contains no malicious code, and all of its operations are fully transparent, the source code is available for full transparency, and well-documented to the best of my ability.

## Requirements

- Windows 10 or later
- Administrator privileges (required to modify network configuration)
- Python 3.8+ with PySide6 installed (or use the standalone executable)

### Optional: Cloudflare Tunnel

For internet exposure features:
- `cloudflared.exe` must be installed and available in system PATH or same directory as PortLinker
- Download from: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
- Internet connection required for tunnel functionality
- No Cloudflare account needed (uses quick tunnels)

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

3. (Optional) Install Cloudflare Tunnel for internet exposure features:
   - Download `cloudflared.exe` from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
   - Add to system PATH or place in the same directory as PortLinker.py
   - This step can be skipped if only using local port forwarding

4. Run the application with administrator privileges:
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
   pyinstaller --icon=icon.ico --version-file=version.txt --noconfirm --windowed --clean --name PortLinker PortLinker.py
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

### Using Cloudflare Tunnel

Cloudflare Tunnel allows you to expose local services to the internet without port forwarding or firewall configuration.

1. Navigate to the **"Cloudflare Tunnel"** tab
2. Enter the **Target IP Address** (e.g., your WSL IP like `172.x.x.x` or `127.0.0.1` for localhost)
3. Enter the **Target Port** number of the service you want to expose (e.g., `80`, `3000`, `8080`)
4. Click **"Start Tunnel"** (or **"Mulai Tunnel"** in Indonesian)
5. Wait a few seconds for the tunnel to initialize
6. **Copy the generated tunnel URL** (e.g., `https://xyz.trycloudflare.com`)
7. Share this URL to access your service from anywhere in the world
8. Click **"Stop Tunnel"** (or **"Hentikan Tunnel"**) when finished

**Important Notes:**
- Tunnel URLs are **temporary** and change with each tunnel session
- Tunnels remain active until you stop them or close the application
- No Cloudflare account or authentication required (uses quick tunnels)
- Requires active internet connection

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

#### Exposing Services to the Internet

To make local services publicly accessible via the internet:
1. Use the **Cloudflare Tunnel** tab (no router configuration needed)
2. Enter your local service's IP and port
3. Click **"Start Tunnel"** to get a public HTTPS URL
4. Share the URL with remote team members or external services

**Example Use Cases:**
- Sharing a local development server with remote collaborators
- Testing webhooks from external services (GitHub, Stripe, etc.)
- Providing temporary public access to WSL-hosted applications
- Demoing work-in-progress projects without deployment

**Advantages:**
- No port forwarding or router configuration required
- No firewall changes needed
- Automatic HTTPS encryption
- Works behind NAT and restrictive firewalls
- Temporary URLs that don't expose your network permanently

## Troubleshooting

PortLinker includes a dedicated troubleshooting tab with:
- Network configuration information
- Active port status
- Firewall rule verification
- Common connection issues and solutions

### Port Forwarding Issues

For connection problems:
1. Ensure devices are on the same network
2. Check Windows Firewall settings
3. Verify the correct IP addresses are being used
4. Confirm target services are running and accessible

### Cloudflare Tunnel Issues

If you encounter problems with Cloudflare Tunnel:

**"cloudflared.exe not found" error:**
- Verify cloudflared is installed: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
- Ensure cloudflared.exe is in your system PATH or same directory as PortLinker
- Restart PortLinker after installing cloudflared

**Tunnel fails to start:**
- Check your internet connection
- Verify the target service is running on the specified IP and port
- Try a different port (some ports may be restricted)
- Check Windows Defender or antivirus isn't blocking cloudflared.exe

**Tunnel URL doesn't appear:**
- Wait up to 30 seconds for initialization (tunnel creation takes time)
- Check the status label for error messages
- Verify cloudflared.exe is not blocked by firewall

**Tunnel disconnects unexpectedly:**
- Quick tunnels are temporary by design
- Check internet connection stability
- Restart the tunnel if needed
- For long-running tunnels, consider Cloudflare's authenticated tunnels

**For advanced troubleshooting**, visit Cloudflare Tunnel documentation:
https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/

## How It Works

### Port Forwarding

PortLinker uses Windows' built-in `netsh interface portproxy` commands to create port forwarding rules at the system level. It also manages Windows Firewall rules to ensure forwarded ports are accessible.

**Use port forwarding for:** Local network access (LAN)

### Cloudflare Tunnel

Cloudflare Tunnel creates secure outbound connections from your machine to Cloudflare's edge network. It uses Cloudflare's quick tunnels (trycloudflare.com) which:
- Require **no authentication** or Cloudflare account
- Generate **temporary HTTPS URLs** that change with each session
- Create **secure encrypted tunnels** through Cloudflare's global network
- Work through **NAT and firewalls** (only outbound connection needed)
- Automatically handle **SSL/TLS certificates** (no manual setup)

**Use Cloudflare Tunnel for:** Public internet access from anywhere

### Key Differences

| Feature | Port Forwarding | Cloudflare Tunnel |
|---------|----------------|-------------------|
| **Scope** | Local network only | Public internet |
| **Configuration** | Router & firewall | None required |
| **URL** | Your IP address | Cloudflare subdomain |
| **Security** | Manual SSL setup | Automatic HTTPS |
| **Firewall** | Inbound rules needed | Works through NAT |
| **Persistence** | Permanent rules | Temporary tunnels |

## License

This software is provided as-is under the MIT License. See the LICENSE file for details.
