# PortLinker - A port forwarding and reverse proxy tool
# Copyright (c) 2025 Exp9072 (now JodyPutra-dev)
# Licensed under the MIT License. See the LICENSE file in the project root for full license information.

"""
Firewall management functions for PortLinker application.

This module contains pure Windows Firewall management operations without any UI dependencies.
Functions handle firewall status checking, rule creation, and rule deletion.
"""

import subprocess
import re


def check_firewall_status() -> tuple[bool, str]:
    """
    Check Windows Firewall status and search for existing Port_Switcher rules.
    
    Returns:
        tuple: (firewall_active, rules_output)
               - firewall_active (bool): True if Windows Firewall is active, False otherwise
               - rules_output (str): Output from firewall rules search, empty if no rules found
               Returns (False, "Error message") on failure
    
    Example:
        >>> is_active, rules = check_firewall_status()
        >>> if is_active:
        ...     print("Firewall is active")
        ...     print(f"Existing rules: {rules}")
    """
    try:
        # Check firewall status using legacy command
        firewall_check = subprocess.run(
            ['netsh', 'firewall', 'show', 'state'], 
            shell=True, 
            capture_output=True, 
            text=True
        )
        
        # Also try newer syntax
        firewall_check2 = subprocess.run(
            ['netsh', 'advfirewall', 'show', 'allprofiles'], 
            shell=True, 
            capture_output=True, 
            text=True
        )
        
        # Check if firewall is active
        firewall_active = False
        
        if "ON" in firewall_check.stdout or "ON" in firewall_check2.stdout:
            firewall_active = True
            
        # If active, check if there are rules for our ports
        port_rules = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all', '|', 'findstr', 'Port_Switcher'], 
            shell=True, 
            capture_output=True, 
            text=True
        )
        
        return (firewall_active, port_rules.stdout)
    except:
        return (False, "Error memeriksa status firewall")


def check_firewall_rule_exists(port: int, rule_name_prefix: str = "Port_Switcher") -> bool:
    """
    Check if a firewall rule already exists for a specific port.
    
    Args:
        port: Port number to check
        rule_name_prefix: Prefix for the rule name (default: "Port_Switcher")
    
    Returns:
        bool: True if rule exists, False otherwise
    
    Example:
        >>> if check_firewall_rule_exists(80):
        ...     print("Rule for port 80 already exists")
    """
    try:
        rule_name = f"{rule_name_prefix}_{port}"
        rule_check = subprocess.run([
            'netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name}'
        ], shell=True, capture_output=True, text=True)
        
        # If "No rules match" appears or command fails, rule doesn't exist
        if "No rules match the specified criteria" in rule_check.stdout or rule_check.returncode != 0:
            return False
        return True
    except:
        return False


def add_firewall_rule(port: int, rule_name_prefix: str = "Port_Switcher") -> bool:
    """
    Create a single firewall rule for one port.
    
    Args:
        port: Port number to allow through firewall
        rule_name_prefix: Prefix for the rule name (default: "Port_Switcher")
    
    Returns:
        bool: True on success, False on failure
    
    Example:
        >>> if add_firewall_rule(80):
        ...     print("Successfully added firewall rule for port 80")
    """
    try:
        rule_name = f"{rule_name_prefix}_{port}"
        subprocess.run([
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name={rule_name}', 'dir=in', 'action=allow',
            'protocol=TCP', f'localport={port}'
        ], shell=True, capture_output=True)
        return True
    except:
        return False


def add_firewall_rules(ports: list[int], rule_name_prefix: str = "Port_Switcher") -> tuple[bool, list[str]]:
    """
    Add firewall rules for multiple ports.
    
    This function checks if rules already exist before creating them to avoid duplicates.
    
    Args:
        ports: List of port numbers to allow through firewall
        rule_name_prefix: Prefix for the rule names (default: "Port_Switcher")
    
    Returns:
        tuple: (success, failed_ports)
               - success (bool): True if all rules were added successfully, False if any failed
               - failed_ports (list[str]): List of port numbers (as strings) that failed to add
    
    Example:
        >>> success, failed = add_firewall_rules([80, 443, 9072])
        >>> if success:
        ...     print("All firewall rules added successfully")
        >>> elif failed:
        ...     print(f"Failed to add rules for ports: {', '.join(failed)}")
    """
    failed_ports = []
    
    try:
        for port in ports:
            # Check if rule already exists
            if not check_firewall_rule_exists(port, rule_name_prefix):
                # Add the rule
                if not add_firewall_rule(port, rule_name_prefix):
                    failed_ports.append(str(port))
        
        return (len(failed_ports) == 0, failed_ports)
    except Exception as e:
        # If there's a general error, mark all ports as failed
        return (False, [str(p) for p in ports])


def delete_firewall_rule(port: int, rule_name_prefix: str = "Port_Switcher") -> bool:
    """
    Delete a single firewall rule for one port.
    
    Args:
        port: Port number whose rule should be deleted
        rule_name_prefix: Prefix for the rule name (default: "Port_Switcher")
    
    Returns:
        bool: True on success, False on failure
    
    Example:
        >>> if delete_firewall_rule(80):
        ...     print("Successfully deleted firewall rule for port 80")
    """
    try:
        rule_name = f"{rule_name_prefix}_{port}"
        subprocess.run([
            'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
            f'name={rule_name}'
        ], shell=True, capture_output=True, timeout=5)
        return True
    except:
        return False


def delete_all_port_switcher_firewall_rules(rule_name_prefix: str = "Port_Switcher", 
                                            common_ports: list[int] = None) -> bool:
    """
    Delete all firewall rules starting with the specified prefix.
    
    This function uses multiple deletion strategies to ensure all rules are removed:
    1. PowerShell method: Uses Get-NetFirewallRule to find and remove matching rules
    2. Common ports method: Iterates through common ports and deletes rules using netsh
    3. Regex method: Gets all rules, parses with regex, and deletes each found rule
    
    Args:
        rule_name_prefix: Prefix for the rule names to delete (default: "Port_Switcher")
        common_ports: List of common ports to try deleting (default: [80, 443, 9072, 7760, 7761, 7762, 7763])
    
    Returns:
        bool: True if any method succeeds, False if all methods fail
    
    Example:
        >>> if delete_all_port_switcher_firewall_rules():
        ...     print("All Port_Switcher firewall rules deleted")
        >>> else:
        ...     print("Failed to delete firewall rules")
    """
    if common_ports is None:
        common_ports = [80, 443, 9072, 7760, 7761, 7762, 7763]
    
    try:
        # Strategy 1: Use PowerShell to delete rules by DisplayName
        try:
            powershell_cmd = f'powershell -Command "Get-NetFirewallRule | Where-Object {{ $_.DisplayName -like \'{rule_name_prefix}_*\' }} | Remove-NetFirewallRule -ErrorAction SilentlyContinue"'
            subprocess.run(powershell_cmd, shell=True, capture_output=True, timeout=10)
        except Exception as e:
            print(f"PowerShell method failed: {e}")
        
        # Strategy 2: Delete rules one by one using common port names (as fallback)
        for port in common_ports:
            try:
                rule_name = f"{rule_name_prefix}_{port}"
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name={rule_name}'
                ], shell=True, capture_output=True, timeout=5)
            except Exception as e:
                print(f"Failed to delete rule for port {port}: {e}")
        
        # Strategy 3: Get list of all rules and filter those starting with rule_name_prefix
        try:
            firewall_rules = subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'
            ], shell=True, capture_output=True, text=True, timeout=10)
            
            if firewall_rules.returncode == 0 and firewall_rules.stdout:
                rule_names = re.findall(rf'Rule Name:\s+({rule_name_prefix}_\d+)', firewall_rules.stdout)
                
                for rule_name in rule_names:
                    try:
                        subprocess.run([
                            'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                            f'name="{rule_name}"'
                        ], shell=True, capture_output=True, timeout=5)
                    except Exception as e:
                        print(f"Failed to delete rule {rule_name}: {e}")
        except Exception as e:
            print(f"Regex method failed: {e}")
            
        return True
    except Exception as e:
        print(f"Error in delete_all_port_switcher_firewall_rules: {e}")
        # Don't raise the exception, just return False to prevent crashes
        return False
