# PortLinker - A port forwarding and reverse proxy tool
# Copyright (c) 2025 Exp9072 (now JodyPutra-dev)
# Licensed under the MIT License. See the LICENSE file in the project root for full license information.

"""
Cloudflare Tunnel Manager Module

Manages Cloudflare Tunnel (trycloudflare) quick tunnels for exposing local services.
This is a Windows-specific implementation that uses subprocess management to control
the cloudflared process.

Requirements:
- cloudflared.exe must be installed and available in PATH or in the same directory
- Internet connection for establishing tunnels
- Valid local IP and port to tunnel

Usage:
    manager = CloudflareTunnelManager()
    if manager.start_tunnel("127.0.0.1", 8080):
        url = manager.get_tunnel_url()
        print(f"Tunnel URL: {url}")
    manager.stop_tunnel()
"""

import subprocess
import threading
import re
import time
import shutil
from typing import Optional


class CloudflareTunnelManager:
    """Manages Cloudflare Tunnel quick tunnels for exposing local services."""
    
    def __init__(self):
        """Initialize the Cloudflare Tunnel Manager."""
        self.process: Optional[subprocess.Popen] = None
        self.tunnel_url: Optional[str] = None
        self.is_active: bool = False
        self.output_thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()
    
    @staticmethod
    def is_cloudflared_installed() -> bool:
        """
        Check if cloudflared is installed and available.
        
        Checks both system PATH and current directory for cloudflared.exe.
        
        Returns:
            True if cloudflared is found, False otherwise
        """
        # Check if cloudflared is in PATH
        if shutil.which('cloudflared') is not None:
            return True
        
        # Check for cloudflared.exe in current directory
        import os
        if os.path.exists('cloudflared.exe'):
            return True
        
        # Check in common installation locations (optional)
        common_paths = [
            os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'cloudflared', 'cloudflared.exe'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'cloudflared', 'cloudflared.exe'),
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return True
        
        return False
    
    def start_tunnel(self, ip: str, port: int) -> bool:
        """
        Start a Cloudflare Tunnel to expose a local service.
        
        Args:
            ip: The local IP address to tunnel (e.g., "127.0.0.1", "0.0.0.0")
            port: The local port number (1-65535)
        
        Returns:
            True if tunnel started successfully, False otherwise
        
        Raises:
            No exceptions raised - errors are handled internally
        """
        # Input validation
        if not self._validate_ip(ip):
            print(f"Invalid IP address: {ip}")
            return False
        
        if not isinstance(port, int) or port < 1 or port > 65535:
            print(f"Invalid port number: {port}")
            return False
        
        # Check if tunnel is already running
        with self.lock:
            if self.is_active:
                print("Tunnel is already running")
                return False
        
        try:
            # Build the cloudflared command
            command = ['cloudflared', 'tunnel', '--url', f'http://{ip}:{port}']
            
            # Start the cloudflared process
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
            
            # Set active status
            with self.lock:
                self.is_active = True
                self.tunnel_url = None
            
            # Start output reader thread
            self.output_thread = threading.Thread(
                target=self._read_output,
                daemon=True
            )
            self.output_thread.start()
            
            # Wait for tunnel URL to be captured (up to 30 seconds)
            timeout = 30
            start_time = time.time()
            while time.time() - start_time < timeout:
                with self.lock:
                    if self.tunnel_url is not None:
                        print(f"Tunnel established: {self.tunnel_url}")
                        return True
                
                # Check if process has terminated unexpectedly
                if self.process.poll() is not None:
                    print("Cloudflared process terminated unexpectedly")
                    with self.lock:
                        self.is_active = False
                    return False
                
                time.sleep(0.5)
            
            # Timeout - URL not captured
            print("Timeout: Could not capture tunnel URL within 30 seconds")
            self.stop_tunnel()
            return False
            
        except FileNotFoundError:
            print("Error: cloudflared.exe not found. Please install Cloudflare Tunnel.")
            with self.lock:
                self.is_active = False
            return False
        
        except subprocess.SubprocessError as e:
            print(f"Error starting cloudflared process: {e}")
            with self.lock:
                self.is_active = False
            return False
        
        except Exception as e:
            print(f"Unexpected error starting tunnel: {e}")
            with self.lock:
                self.is_active = False
            return False
    
    def stop_tunnel(self) -> bool:
        """
        Stop the running Cloudflare Tunnel.
        
        Returns:
            True (always) - best effort cleanup
        """
        with self.lock:
            if not self.is_active and self.process is None:
                return True
        
        try:
            # Attempt graceful termination
            if self.process is not None:
                print("Stopping Cloudflare Tunnel...")
                
                # First try terminate()
                self.process.terminate()
                
                try:
                    # Wait up to 5 seconds for graceful shutdown
                    self.process.wait(timeout=5)
                    print("Tunnel stopped gracefully")
                except subprocess.TimeoutExpired:
                    # Force kill if still running
                    print("Forcing tunnel termination...")
                    self.process.kill()
                    
                    # Try Windows-specific task kill for process tree
                    try:
                        subprocess.run(
                            ['taskkill', '/F', '/T', '/PID', str(self.process.pid)],
                            capture_output=True,
                            timeout=3
                        )
                    except:
                        pass
                    
                    # Final wait
                    try:
                        self.process.wait(timeout=2)
                    except:
                        pass
        
        except Exception as e:
            print(f"Error stopping tunnel: {e}")
        
        finally:
            # Cleanup regardless of errors
            with self.lock:
                self.is_active = False
                self.tunnel_url = None
                self.process = None
            
            # Join output thread if exists
            if self.output_thread is not None and self.output_thread.is_alive():
                self.output_thread.join(timeout=2)
                self.output_thread = None
            
            print("Tunnel cleanup completed")
        
        return True
    
    def is_running(self) -> bool:
        """
        Check if the tunnel is currently running.
        
        Returns:
            True if tunnel is active and process is running, False otherwise
        """
        with self.lock:
            if not self.is_active or self.process is None:
                return False
            
            # Check if process has terminated
            if self.process.poll() is not None:
                self.is_active = False
                return False
            
            return True
    
    def get_tunnel_url(self) -> Optional[str]:
        """
        Get the current tunnel URL.
        
        Returns:
            The tunnel URL (e.g., "https://xyz.trycloudflare.com") or None if not available
        """
        with self.lock:
            return self.tunnel_url
    
    def _read_output(self):
        """
        Read stdout and stderr from cloudflared process and parse for tunnel URL.
        This method runs in a separate daemon thread.
        """
        if self.process is None:
            return
        
        try:
            # Read from both stdout and stderr
            for line in self.process.stderr:
                if line:
                    line = line.strip()
                    print(f"[cloudflared] {line}")
                    
                    # Try to parse tunnel URL from output
                    url = self._parse_tunnel_url(line)
                    if url:
                        with self.lock:
                            if self.tunnel_url is None:  # Only set once
                                self.tunnel_url = url
                                print(f"Captured tunnel URL: {url}")
                
                # Stop reading if process is no longer active
                with self.lock:
                    if not self.is_active:
                        break
        
        except Exception as e:
            print(f"Error reading cloudflared output: {e}")
    
    def _parse_tunnel_url(self, output: str) -> Optional[str]:
        """
        Parse tunnel URL from cloudflared output.
        
        Args:
            output: A line of output from cloudflared
        
        Returns:
            The extracted tunnel URL or None if no URL found
        """
        # Look for trycloudflare.com URL pattern
        match = re.search(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com', output)
        if match:
            return match.group(0)
        
        return None
    
    def _validate_ip(self, ip: str) -> bool:
        """
        Basic IP address validation.
        
        Args:
            ip: IP address string to validate
        
        Returns:
            True if IP format appears valid, False otherwise
        """
        if not ip:
            return False
        
        # Allow common patterns: 0.0.0.0, 127.0.0.1, or any IPv4
        # Simple regex check for IPv4 format
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, ip):
            # Check each octet is 0-255
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        
        return False


# Test code for standalone execution
if __name__ == "__main__":
    print("Cloudflare Tunnel Manager Test")
    print("-" * 50)
    
    manager = CloudflareTunnelManager()
    
    # Test with localhost
    print("\nStarting tunnel for localhost:8080...")
    if manager.start_tunnel("127.0.0.1", 8080):
        print(f"✓ Tunnel started successfully")
        print(f"✓ URL: {manager.get_tunnel_url()}")
        print(f"✓ Status: {'Running' if manager.is_running() else 'Stopped'}")
        
        # Keep tunnel running for a bit
        print("\nTunnel will run for 10 seconds...")
        time.sleep(10)
        
        # Stop tunnel
        print("\nStopping tunnel...")
        manager.stop_tunnel()
        print(f"✓ Status: {'Running' if manager.is_running() else 'Stopped'}")
    else:
        print("✗ Failed to start tunnel")
        print("  Make sure cloudflared is installed and port 8080 is available")
