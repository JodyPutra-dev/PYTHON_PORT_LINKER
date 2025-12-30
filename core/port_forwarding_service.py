# PortLinker - A port forwarding and reverse proxy tool
# Copyright (c) 2025 Exp9072 (now JodyPutra-dev)
# Licensed under the MIT License. See the LICENSE file in the project root for full license information.

"""
Port forwarding service module.

This module provides a service class for managing Windows port forwarding operations
using netsh commands. It separates business logic from UI concerns.
"""

import subprocess
import re
from typing import Optional

from config import DEFAULT_PORTS
from core.network_utils import parse_port_string, get_network_info
from core.firewall_manager import (
    check_firewall_status,
    add_firewall_rules,
    delete_firewall_rule,
    delete_all_port_switcher_firewall_rules
)


class PortForwardingService:
    """
    Service class for managing port forwarding operations.
    Pure business logic without UI dependencies.
    """
    
    def __init__(self):
        """Initialize the port forwarding service."""
        pass
    
    def parse_ports(self, port_text: str) -> list[int]:
        """
        Parse port string to list of port numbers.
        
        Args:
            port_text: Port string (e.g., "80,443,8080-8090")
            
        Returns:
            List of port numbers
            
        Raises:
            ValueError: If port format is invalid
        """
        ports = parse_port_string(port_text)
        if not ports:
            raise ValueError("Invalid port format")
        return ports
    
    def validate_ports(self, ports: list[int]) -> tuple[bool, str]:
        """
        Validate port list.
        
        Args:
            ports: List of port numbers to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not ports:
            return (False, "No ports specified")
        return (True, "")
    
    def enable_forwarding(
        self,
        listen_ip: str,
        target_ip: str,
        ports: list[int]
    ) -> dict:
        """
        Enable port forwarding for specified ports.
        
        Args:
            listen_ip: IP address to listen on (or 0.0.0.0 for all interfaces)
            target_ip: Target IP address to forward to
            ports: List of port numbers to forward
            
        Returns:
            Dictionary with results:
            {
                "success": bool,
                "error": str or None,
                "firewall_active": bool,
                "firewall_success": bool,
                "failed_firewall_ports": list[int],
                "network_info": tuple
            }
        """
        result = {
            "success": False,
            "error": None,
            "firewall_active": False,
            "firewall_success": False,
            "failed_firewall_ports": [],
            "network_info": None
        }
        
        # Validate inputs
        if not target_ip or target_ip.strip() == "":
            result["error"] = "Target IP address is required"
            return result
        
        is_valid, error_msg = self.validate_ports(ports)
        if not is_valid:
            result["error"] = error_msg
            return result
        
        try:
            # Delete existing rules for these ports first
            for port in ports:
                # Try deleting for specific listen IP
                try:
                    subprocess.run([
                        "netsh", "interface", "portproxy", "delete", "v4tov4",
                        f"listenport={port}", f"listenaddress={listen_ip}"
                    ], check=False, capture_output=True, timeout=5)
                except Exception:
                    pass
                
                # Also try deleting for 0.0.0.0
                try:
                    subprocess.run([
                        "netsh", "interface", "portproxy", "delete", "v4tov4",
                        f"listenport={port}", "listenaddress=0.0.0.0"
                    ], check=False, capture_output=True, timeout=5)
                except Exception:
                    pass
            
            # Add new port forwarding rules
            for port in ports:
                # Always add for all interfaces (0.0.0.0)
                subprocess.check_output([
                    "netsh", "interface", "portproxy", "add", "v4tov4",
                    f"listenport={port}", "listenaddress=0.0.0.0",
                    f"connectport={port}", f"connectaddress={target_ip}"
                ], stderr=subprocess.STDOUT)
            
            # Check firewall status and add rules if active
            firewall_active, rules = check_firewall_status()
            result["firewall_active"] = firewall_active
            
            if firewall_active:
                success, failed_ports = add_firewall_rules(ports)
                result["firewall_success"] = success
                result["failed_firewall_ports"] = failed_ports
            
            # Get network information
            result["network_info"] = get_network_info()
            
            # Mark as successful
            result["success"] = True
            
        except subprocess.CalledProcessError as e:
            result["error"] = f"Failed to create port forwarding: {e.output.decode('utf-8', errors='ignore')}"
        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
        
        return result
    
    def disable_forwarding(
        self,
        ports: list[int],
        listen_ip: str,
        delete_all: bool = False
    ) -> dict:
        """
        Disable port forwarding for specified ports or all rules.
        
        Args:
            ports: List of port numbers to disable (used when delete_all=False)
            listen_ip: IP address that was listening
            delete_all: If True, delete all port forwarding rules
            
        Returns:
            Dictionary with results:
            {
                "success": bool,
                "error": str or None,
                "deleted_ports": list[int],
                "deletion_errors": list[str]
            }
        """
        result = {
            "success": False,
            "error": None,
            "deleted_ports": [],
            "deletion_errors": []
        }
        
        try:
            if delete_all:
                # Delete all port forwarding with reset
                try:
                    subprocess.run([
                        "netsh", "interface", "portproxy", "reset"
                    ], check=False, capture_output=True, timeout=5)
                    result["deleted_ports"] = []  # All ports deleted
                except Exception as e:
                    result["deletion_errors"].append(f"Failed to reset port proxy: {str(e)}")
                
                # Delete all firewall rules
                try:
                    delete_all_port_switcher_firewall_rules()
                except Exception as e:
                    result["deletion_errors"].append(f"Failed to delete all firewall rules: {str(e)}")
            else:
                # Delete specific port rules
                for port in ports:
                    # Try deleting for specific listen IP
                    try:
                        subprocess.run([
                            "netsh", "interface", "portproxy", "delete", "v4tov4",
                            f"listenport={port}", f"listenaddress={listen_ip}"
                        ], check=False, capture_output=True, timeout=5)
                        result["deleted_ports"].append(port)
                    except Exception as e:
                        result["deletion_errors"].append(f"Failed to delete port proxy for {port}: {str(e)}")
                    
                    # Also try deleting for 0.0.0.0
                    try:
                        subprocess.run([
                            "netsh", "interface", "portproxy", "delete", "v4tov4",
                            f"listenport={port}", "listenaddress=0.0.0.0"
                        ], check=False, capture_output=True, timeout=5)
                    except Exception:
                        pass
                    
                    # Delete firewall rule for this port
                    try:
                        rule_name = f"Port_Switcher_{port}"
                        if not delete_firewall_rule(rule_name):
                            result["deletion_errors"].append(f"Failed to delete firewall rule for port {port}")
                    except Exception as e:
                        result["deletion_errors"].append(f"Failed to delete firewall rule for port {port}: {str(e)}")
                
                # Clean up any remaining firewall rules
                try:
                    delete_all_port_switcher_firewall_rules()
                except Exception as e:
                    result["deletion_errors"].append(f"Failed to delete all firewall rules: {str(e)}")
            
            result["success"] = True
            
        except Exception as e:
            result["error"] = f"Critical error: {str(e)}"
        
        return result
    
    def get_current_rules(self) -> tuple[bool, str]:
        """
        Get current port proxy rules from netsh.
        
        Returns:
            Tuple of (success, rules_output)
        """
        try:
            result = subprocess.check_output(
                ["netsh", "interface", "portproxy", "show", "all"],
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                timeout=10
            )
            return (True, result)
        except subprocess.CalledProcessError as e:
            return (False, f"Error retrieving rules: {str(e)}")
        except Exception as e:
            return (False, f"Unexpected error: {str(e)}")
    
    def get_active_forwarding_rules(self) -> list[dict]:
        """
        Parse and return structured list of active port forwarding rules.
        
        Returns:
            List of dictionaries with rule details:
            [
                {
                    "listen_ip": str,
                    "listen_port": int,
                    "target_ip": str,
                    "target_port": int
                },
                ...
            ]
        """
        success, rules_output = self.get_current_rules()
        if not success:
            return []
        
        rules = []
        # Parse netsh output
        # Example line: "0.0.0.0            80                127.0.0.1          80"
        lines = rules_output.split('\n')
        for line in lines:
            # Match IP:Port patterns
            match = re.match(r'\s*(\S+)\s+(\d+)\s+(\S+)\s+(\d+)', line)
            if match:
                rules.append({
                    "listen_ip": match.group(1),
                    "listen_port": int(match.group(2)),
                    "target_ip": match.group(3),
                    "target_port": int(match.group(4))
                })
        
        return rules
    
    def delete_specific_rule(self, listen_ip: str, listen_port: int) -> bool:
        """
        Delete a single specific port proxy rule.
        
        Args:
            listen_ip: IP address that's listening
            listen_port: Port number that's listening
            
        Returns:
            True if successful, False otherwise
        """
        try:
            subprocess.run([
                "netsh", "interface", "portproxy", "delete", "v4tov4",
                f"listenport={listen_port}", f"listenaddress={listen_ip}"
            ], check=True, capture_output=True, timeout=5)
            return True
        except Exception:
            return False
