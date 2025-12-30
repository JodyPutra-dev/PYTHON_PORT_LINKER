# PortLinker - A port forwarding and reverse proxy tool
# Copyright (c) 2025 Exp9072 (now JodyPutra-dev)
# Licensed under the MIT License. See the LICENSE file in the project root for full license information.

"""
Core package for PortLinker application.

This package contains pure business logic and utility functions
without any UI dependencies.

Exported modules:
    - network_utils: Network operations and device management

Public API:
    - get_local_ip: Get the local IP address of the machine
    - get_network_info: Get network configuration information
    - check_port_in_use: Check if a port is currently in use
    - get_process_using_port: Identify process using a specific port
    - kill_process_by_pid: Kill a process by its PID
    - parse_port_string: Parse port selection strings
    - get_connected_devices: Get list of network devices
    - resolve_hostname: Resolve hostname for an IP address
    - is_xampp_running: Check if XAMPP is running
    - get_xampp_paths: Get common XAMPP installation paths
    - stop_xampp_services: Stop XAMPP services
"""

from .network_utils import (
    get_local_ip,
    get_network_info,
    check_port_in_use,
    get_process_using_port,
    kill_process_by_pid,
    parse_port_string,
    get_connected_devices,
    resolve_hostname,
    is_xampp_running,
    get_xampp_paths,
    stop_xampp_services
)

__all__ = [
    "get_local_ip",
    "get_network_info",
    "check_port_in_use",
    "get_process_using_port",
    "kill_process_by_pid",
    "parse_port_string",
    "get_connected_devices",
    "resolve_hostname",
    "is_xampp_running",
    "get_xampp_paths",
    "stop_xampp_services"
]
