# PortLinker - A port forwarding and reverse proxy tool
# Copyright (c) 2025 Exp9072 (now JodyPutra-dev)
# Licensed under the MIT License. See the LICENSE file in the project root for full license information.

"""
Network utility functions for PortLinker application.

This module contains pure network operations without any UI dependencies.
Functions handle IP detection, port management, device discovery, and XAMPP control.
"""

import socket
import subprocess
import re
import os


def get_local_ip() -> str:
    """
    Get the local IP address of the device connected to the network.
    
    Returns:
        str: Local IP address. Falls back to "192.168.0.2" if all methods fail.
    
    Example:
        >>> ip = get_local_ip()
        >>> print(ip)
        '192.168.1.100'
    """
    try:
        # Method 1: Create dummy connection to get IP used for network communication
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Address doesn't need to be reachable, this is just to get the default interface
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        try:
            # Method 2: Use hostname if method 1 fails
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            return local_ip
        except:
            try:
                # Method 3: Check all IP addresses associated with hostname
                hostname = socket.gethostname()
                ip_addresses = socket.gethostbyname_ex(hostname)
                if ip_addresses and len(ip_addresses) > 1 and ip_addresses[2]:
                    # Choose the first non-localhost IP address
                    for ip in ip_addresses[2]:
                        if not ip.startswith("127."):
                            return ip
                    # If all are localhost, use the first one
                    return ip_addresses[2][0]
            except:
                pass
    
    # If all methods fail, use localhost as fallback
    return "192.168.0.2"


def get_network_info() -> tuple[str, tuple, str]:
    """
    Get network information to help diagnose connection issues.
    
    Returns:
        tuple: (hostname, ip_addresses, ipconfig_output)
               Returns (None, None, error_message) on failure
    
    Example:
        >>> hostname, ips, config = get_network_info()
        >>> print(hostname)
        'DESKTOP-ABC123'
    """
    try:
        # Get IP addresses
        hostname = socket.gethostname()
        ip_addresses = socket.gethostbyname_ex(hostname)
        
        # Get active network interfaces
        ipconfig = subprocess.run(
            ['ipconfig'], 
            shell=True, 
            capture_output=True, 
            text=True
        )
        
        return (hostname, ip_addresses, ipconfig.stdout)
    except Exception as e:
        return (None, None, str(e))


def check_port_in_use(port: int) -> bool:
    """
    Check if a port is currently in use by another process.
    
    Args:
        port: Port number to check
    
    Returns:
        bool: True if port is in use, False otherwise
    
    Example:
        >>> check_port_in_use(80)
        True
    """
    try:
        # Check if port is in use
        port_check = subprocess.run(
            ['netstat', '-ano', '|', 'findstr', f':{port}'], 
            shell=True, 
            capture_output=True, 
            text=True
        )
        return "LISTENING" in port_check.stdout
    except:
        return False


def kill_process_by_pid(pid: int) -> bool:
    """
    Kill a process by its PID.
    
    Args:
        pid: Process ID to kill
    
    Returns:
        bool: True on success, False on failure
    
    Example:
        >>> kill_process_by_pid(1234)
        True
    """
    try:
        subprocess.run(['taskkill', '/F', '/PID', str(pid)], 
                      shell=True, 
                      capture_output=True)
        return True
    except:
        return False


def get_process_using_port(port: int) -> tuple[str, str | None]:
    """
    Identify the process using a specific port.
    
    Args:
        port: Port number to check
    
    Returns:
        tuple: (process_description, pid)
               Returns ("Tidak ada proses", None) if port is free
               Returns ("Proses tidak dikenal", None) on error
    
    Example:
        >>> desc, pid = get_process_using_port(80)
        >>> print(desc)
        'httpd.exe (PID: 1234)'
    """
    try:
        # Get the process ID using the port
        netstat_output = subprocess.run(
            ['netstat', '-ano', '|', 'findstr', f':{port}'], 
            shell=True, 
            capture_output=True, 
            text=True
        )
        
        if "LISTENING" not in netstat_output.stdout:
            return "Tidak ada proses", None
            
        # Extract PID from netstat output
        lines = netstat_output.stdout.strip().split('\n')
        for line in lines:
            if f':{port}' in line and 'LISTENING' in line:
                parts = line.strip().split()
                if len(parts) >= 5:
                    pid = parts[-1]
                    
                    # Get process name from PID
                    tasklist_output = subprocess.run(
                        ['tasklist', '/FI', f'PID eq {pid}'], 
                        shell=True, 
                        capture_output=True, 
                        text=True
                    )
                    
                    # Extract process name
                    if pid in tasklist_output.stdout:
                        process_line = [line for line in tasklist_output.stdout.split('\n') 
                                      if pid in line][0]
                        process_name = process_line.split()[0]
                        return f"{process_name} (PID: {pid})", pid
        
        return "Proses tidak dikenal", None
    except Exception as e:
        return f"Error mengidentifikasi proses: {str(e)}", None


def parse_port_string(port_text: str, default_ports: list[int]) -> list[int]:
    """
    Parse a port selection string into a list of integer ports.
    
    Supports multiple formats:
    - "all" - returns default_ports
    - Single port: "8080"
    - Comma-separated: "80, 443, 8080"
    - Ranges: "8000-8010"
    - Combinations: "80, 443, 8000-8010, 9072"
    
    Args:
        port_text: Text string containing port specifications
        default_ports: List of default ports to use for "all" or empty input
    
    Returns:
        list: List of unique integer port numbers
    
    Raises:
        ValueError: If port format is invalid
    
    Example:
        >>> parse_port_string("80, 443, 8000-8005", [80, 443, 9072])
        [80, 443, 8000, 8001, 8002, 8003, 8004, 8005]
    """
    # If empty, use default ports
    if not port_text:
        return default_ports
        
    # If "all", use default ports
    if port_text.lower() == "all":
        return default_ports
        
    # Process port string
    port_list = []
    for part in port_text.split(','):
        part = part.strip()
        
        # Check if this is a port range (e.g., 8000-8005)
        if '-' in part:
            try:
                start, end = part.split('-')
                start_port = int(start.strip())
                end_port = int(end.strip())
                # Add all ports in the range
                port_list.extend(range(start_port, end_port + 1))
            except ValueError:
                raise ValueError(f"Invalid port range format: {part}")
        else:
            # Single port
            try:
                port_list.append(int(part))
            except ValueError:
                raise ValueError(f"Port must be a number: {part}")
                
    # Remove duplicates
    port_list = list(set(port_list))
    
    # Validate
    if not port_list:
        return default_ports
        
    return port_list


def get_connected_devices() -> list[dict]:
    """
    Get a list of devices connected to the same network.
    
    Returns:
        list: List of device dictionaries with keys: "ip", "mac", "hostname"
              Hostname is initially empty (use resolve_hostname to populate)
              Returns empty list on error
    
    Example:
        >>> devices = get_connected_devices()
        >>> for device in devices:
        ...     print(f"{device['ip']} - {device['mac']}")
        192.168.1.1 - aa-bb-cc-dd-ee-ff
    """
    connected_devices = []
    try:
        # Using arp -a to get the list of devices on the network
        arp_result = subprocess.run(
            ['arp', '-a'], 
            shell=True, 
            capture_output=True, 
            text=True,
            timeout=5  # Reduce timeout to prevent long hangs
        )
        
        if arp_result.returncode == 0:
            # Parse the output for IP and MAC addresses
            for line in arp_result.stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("Interface"):
                    parts = [p for p in line.split() if p.strip()]
                    if len(parts) >= 2:
                        ip_address = parts[0]
                        mac_address = parts[1]
                        if mac_address != "ff-ff-ff-ff-ff-ff" and not ip_address.startswith("224."):
                            # Skip hostname resolution for faster results
                            device_info = {
                                "ip": ip_address,
                                "mac": mac_address,
                                "hostname": ""
                            }
                            connected_devices.append(device_info)
        
        return connected_devices
    except Exception as e:
        print(f"Error getting connected devices: {str(e)}")
        return []


def resolve_hostname(ip_address: str, timeout_ms: int = 500) -> str:
    """
    Resolve hostname for a given IP address.
    
    Args:
        ip_address: IP address to resolve
        timeout_ms: Timeout in milliseconds for the ping command (default: 500)
    
    Returns:
        str: Hostname if resolved, empty string otherwise
    
    Example:
        >>> hostname = resolve_hostname("192.168.1.1", timeout_ms=500)
        >>> print(hostname)
        'router.local'
    """
    try:
        hostname_result = subprocess.run(
            ['ping', '-a', '-n', '1', '-w', str(timeout_ms), ip_address],
            shell=True,
            capture_output=True,
            text=True,
            timeout=0.8  # Shorter timeout
        )
        
        # Extract hostname from ping output
        if hostname_result.returncode == 0:
            ping_output = hostname_result.stdout
            hostname_match = re.search(r'Pinging ([^\s]+) \[', ping_output)
            if hostname_match:
                return hostname_match.group(1)
    except:
        pass  # Just skip on error
    
    return ""


def is_xampp_running() -> bool:
    """
    Check if XAMPP is currently running.
    
    Returns:
        bool: True if XAMPP (httpd.exe) is detected, False otherwise
    
    Example:
        >>> is_xampp_running()
        False
    """
    try:
        # Check for httpd.exe process
        process_check = subprocess.run(
            ['tasklist', '|', 'findstr', 'httpd.exe'], 
            shell=True, 
            capture_output=True, 
            text=True
        )
        return 'httpd.exe' in process_check.stdout
    except:
        return False


def get_xampp_paths() -> list[str]:
    """
    Get list of common XAMPP installation paths.
    
    Returns:
        list: List of common XAMPP executable paths
    
    Example:
        >>> paths = get_xampp_paths()
        >>> print(paths)
        ['C:\\\\xampp\\\\xampp_stop.exe', 'C:\\\\xampp\\\\xampp-control.exe']
    """
    return [
        r"C:\xampp\xampp_stop.exe",
        r"C:\xampp\xampp-control.exe",
    ]


def stop_xampp_services() -> bool:
    """
    Stop XAMPP services (Apache and related processes).
    
    Returns:
        bool: True if services were stopped successfully, False otherwise
    
    Example:
        >>> stop_xampp_services()
        True
    """
    try:
        # Try common XAMPP stop methods
        xampp_paths = get_xampp_paths()
        
        for path in xampp_paths:
            if os.path.exists(path):
                subprocess.run([path], 
                              shell=True, 
                              capture_output=True)
                
        # Try to stop Apache service if exists
        subprocess.run(
            ["net", "stop", "Apache2.4"], 
            shell=True, 
            capture_output=True
        )
        
        # Finally: Kill all Apache processes
        subprocess.run(
            ["taskkill", "/F", "/IM", "httpd.exe"], 
            shell=True, 
            capture_output=True
        )
        
        return True
    except:
        return False
