# PortLinker - A port forwarding and reverse proxy tool
# Copyright (c) 2025 Exp9072 (now JodyPutra-dev)
# Licensed under the MIT License. See the LICENSE file in the project root for full license information.

import os
import subprocess
import sys
import time
import datetime
import threading
import zipfile
import logging
import shutil
import ctypes
from pathlib import Path
from ctypes import wintypes

# Windows Job Object API constants and functions for process management
PROCESS_TERMINATE = 0x0001
PROCESS_SET_QUOTA = 0x0100
PROCESS_ALL_ACCESS = 0x001F0FFF
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# Define function prototypes
kernel32.CreateJobObjectW.restype = wintypes.HANDLE
kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]

kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]

kernel32.SetInformationJobObject.restype = wintypes.BOOL
kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]

kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

# Define the structure for job object extended limit information
class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
        ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", wintypes.SIZE),
        ("MaximumWorkingSetSize", wintypes.SIZE),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", wintypes.PULONG),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD)
    ]

class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong)
    ]

class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", wintypes.SIZE),
        ("JobMemoryLimit", wintypes.SIZE),
        ("PeakProcessMemoryUsed", wintypes.SIZE),
        ("PeakJobMemoryUsed", wintypes.SIZE)
    ]

JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9

class CaddyManager:
    def __init__(self, caddy_dir="caddy", max_log_files=3, max_archive_files=3):
        """
        Initialize the Caddy server manager
        
        Args:
            caddy_dir: Directory where caddy.exe is located
            max_log_files: Maximum number of log files to keep (caddy.log, caddy.log.1, etc.)
            max_archive_files: Maximum number of archived log files (.7z files)
        """
        # Convert to absolute path and normalize
        try:
            # Get the absolute path of the workspace
            workspace_dir = Path(os.getcwd()).absolute()
            print(f"Workspace directory: {workspace_dir}")
            
            # Convert caddy_dir to absolute path
            self.caddy_dir = (workspace_dir / caddy_dir).resolve()
            print(f"Caddy directory: {self.caddy_dir}")
            
            # Set up other paths
            self.caddy_exe = self.caddy_dir / "caddy_windows_amd64.exe"
            self.caddy_config = self.caddy_dir / "Caddyfile"
            self.log_dir = self.caddy_dir / "logs"
            self.log_file = self.log_dir / "caddy.log"
            
            print(f"Caddy executable: {self.caddy_exe}")
            print(f"Caddy config: {self.caddy_config}")
            print(f"Log directory: {self.log_dir}")
            print(f"Log file: {self.log_file}")
            
            # Verify directories and files
            if not self.caddy_dir.exists():
                print(f"Creating Caddy directory: {self.caddy_dir}")
                self.caddy_dir.mkdir(parents=True, exist_ok=True)
            
            if not self.log_dir.exists():
                print(f"Creating logs directory: {self.log_dir}")
                self.log_dir.mkdir(parents=True, exist_ok=True)
            
            # Verify Caddy executable
            if not self.caddy_exe.exists():
                raise FileNotFoundError(
                    f"Caddy executable not found at: {self.caddy_exe}\n"
                    "Please make sure:\n"
                    f"1. The file 'caddy_windows_amd64.exe' exists in {self.caddy_dir}\n"
                    "2. You have downloaded the correct version of Caddy for Windows\n"
                    "3. The file has not been renamed"
                )
            
            # Verify executable permissions
            if not os.access(str(self.caddy_exe), os.X_OK):
                print(f"Warning: Caddy executable might not have execute permissions: {self.caddy_exe}")
            
            # Initialize other variables
            self.max_log_files = max_log_files
            self.max_archive_files = max_archive_files
            self.process = None
            self.job_handle = None
            
            # Configure logging
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(self.log_file),
                    logging.StreamHandler()
                ]
            )
            self.logger = logging.getLogger("CaddyManager")
            
            # Test Caddy executable
            print("\nTesting Caddy executable...")
            test_result = subprocess.run(
                [str(self.caddy_exe), "version"],
                capture_output=True,
                text=True,
                cwd=str(self.caddy_dir)
            )
            
            if test_result.returncode == 0:
                print(f"Caddy version: {test_result.stdout.strip()}")
            else:
                print(f"Error testing Caddy: {test_result.stderr}")
                raise RuntimeError(f"Failed to run Caddy: {test_result.stderr}")
                
        except Exception as e:
            print(f"Error initializing CaddyManager: {e}")
            raise

    def _create_job_object(self):
        """Create a Windows Job Object to automatically terminate child processes"""
        job_handle = kernel32.CreateJobObjectW(None, None)
        if job_handle == 0:
            self.logger.error(f"Failed to create job object: {ctypes.get_last_error()}")
            return None
            
        # Configure the job to kill processes when the job is closed
        job_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        
        result = kernel32.SetInformationJobObject(
            job_handle,
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(job_info),
            ctypes.sizeof(job_info)
        )
        
        if result == 0:
            self.logger.error(f"Failed to set job information: {ctypes.get_last_error()}")
            kernel32.CloseHandle(job_handle)
            return None
            
        return job_handle

    def _assign_process_to_job(self, process_id):
        """Assign a process to the job object"""
        if not self.job_handle:
            self.logger.error("No job handle available")
            return False
            
        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if process_handle == 0:
            self.logger.error(f"Failed to open process {process_id}: {ctypes.get_last_error()}")
            return False
            
        result = kernel32.AssignProcessToJobObject(self.job_handle, process_handle)
        kernel32.CloseHandle(process_handle)
        
        if result == 0:
            self.logger.error(f"Failed to assign process to job: {ctypes.get_last_error()}")
            return False
            
        return True

    def rotate_logs(self):
        """Rotate log files and archive old logs"""
        # Check if the main log file exists
        if not self.log_file.exists():
            return
            
        # Check size - only rotate if file is larger than 10MB
        if self.log_file.stat().st_size < 10 * 1024 * 1024:  # 10MB in bytes
            return
            
        # Rotate existing log files
        for i in range(self.max_log_files - 1, 0, -1):
            current = self.log_dir / f"caddy.log.{i}"
            next_file = self.log_dir / f"caddy.log.{i+1}"
            
            if current.exists():
                if i == self.max_log_files - 1:
                    # Archive the oldest log file
                    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    archive_name = self.log_dir / f"logs_{timestamp}.7z"
                    
                    try:
                        # Create a 7z archive using py7zr
                        with zipfile.ZipFile(archive_name, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
                            zipf.write(current, arcname=current.name)
                        
                        # Remove the original log file after archiving
                        current.unlink()
                        
                        # Manage archive count
                        self._manage_archives()
                    except Exception as e:
                        self.logger.error(f"Failed to archive log file: {e}")
                else:
                    # Rename file to next index
                    shutil.move(str(current), str(next_file))
        
        # Rename the current log file
        next_file = self.log_dir / "caddy.log.1"
        shutil.move(str(self.log_file), str(next_file))
        
        # Create a new empty log file
        self.log_file.touch()

    def _manage_archives(self):
        """Keep only the specified number of archive files"""
        archives = sorted([
            f for f in self.log_dir.glob("logs_*.7z")
        ])
        
        # Remove oldest archives if we have too many
        while len(archives) > self.max_archive_files:
            try:
                archives[0].unlink()
                archives = archives[1:]
            except Exception as e:
                self.logger.error(f"Failed to delete old archive: {e}")
                break

    def generate_caddyfile(self, listen_ip, ports, target_ip):
        """
        Generate a Caddyfile for the given configuration
        
        Args:
            listen_ip: The IP to listen on (your PC's public IP)
            ports: List of ports to forward
            target_ip: The target IP to forward to (e.g., WSL IP)
        """
        # Get absolute path to log file and ensure forward slashes
        log_path = str(self.log_file.resolve()).replace('\\', '/')
        
        caddyfile_content = f"""# Global options
{{
    admin off
    local_certs
    auto_https disable_redirects
    log {{
        output file "{log_path}"
        format json
        level INFO
    }}
}}

# Rate limiting configuration - applied to ALL requests
(rate_limit) {{
    rate_limit {{
        zone requests {{
            key {{remote_ip}}
            requests 30
            window 1m
            burst 10
        }}
    }}
}}

# Security headers
(security_headers) {{
    header {{
        # Enable HSTS
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        # Prevent clickjacking
        X-Frame-Options "DENY"
        # Enable XSS protection
        X-XSS-Protection "1; mode=block"
        # Prevent MIME type sniffing
        X-Content-Type-Options "nosniff"
        # Referrer policy
        Referrer-Policy "strict-origin-when-cross-origin"
        # Content Security Policy
        Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'"
    }}
}}

# Main server block - handles ALL traffic
{{
    # Apply rate limiting to ALL requests
    import rate_limit
    import security_headers
    
    # Handle HTTP (port 80) with redirect to HTTPS
    :80 {{
        redir https://{{host}}:443{{uri}} permanent
    }}
    
    # Handle HTTPS (port 443)
    :443 {{
        reverse_proxy https://{target_ip} {{
            transport http {{
                tls_insecure_skip_verify
            }}
        }}
    }}
    
    # Handle port 9072
    :9072 {{
        reverse_proxy https://{target_ip} {{
            transport http {{
                tls_insecure_skip_verify
            }}
        }}
    }}
}}
"""
        
        # Write the Caddyfile
        with open(self.caddy_config, 'w') as f:
            f.write(caddyfile_content)
            
        self.logger.info(f"Generated Caddyfile for {listen_ip} -> {target_ip} with ports {ports}")

    def start_caddy(self):
        """Start the Caddy server using the generated Caddyfile"""
        if self.process and self.process.poll() is None:
            print("Caddy is already running. Stopping it first.")
            self.stop_caddy()
            
        # Rotate logs before starting
        self.rotate_logs()
        
        try:
            # Print current working directory and paths
            print("\nStarting Caddy:")
            print(f"Current working directory: {os.getcwd()}")
            print(f"Caddy directory: {self.caddy_dir}")
            print(f"Caddy executable: {self.caddy_exe}")
            print(f"Caddy config: {self.caddy_config}")
            
            # Verify Caddy executable exists and is accessible
            if not self.caddy_exe.exists():
                print(f"ERROR: Caddy executable not found at: {self.caddy_exe}")
                return False
                
            if not os.access(str(self.caddy_exe), os.X_OK):
                print(f"ERROR: Caddy executable is not executable: {self.caddy_exe}")
                return False

            # Verify Caddyfile exists and is readable
            if not self.caddy_config.exists():
                print(f"ERROR: Caddyfile not found at: {self.caddy_config}")
                return False

            # Print the Caddyfile content for debugging
            with open(self.caddy_config, 'r') as f:
                caddyfile_content = f.read()
                print("\nCaddyfile content:")
                print(caddyfile_content)
                print("\n")
                
            # Start Caddy with the Caddyfile
            print("\nStarting Caddy server...")
            try:
                self.process = subprocess.Popen(
                    [
                        str(self.caddy_exe),
                        "run",
                        "--config", str(self.caddy_config),
                        "--adapter", "caddyfile"
                    ],
                    cwd=str(self.caddy_dir),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
                )
            except Exception as e:
                print(f"Error starting Caddy: {e}")
                return False
            
            # Create a job object with proper error handling
            try:
                self.job_handle = self._create_job_object()
                if self.job_handle:
                    success = self._assign_process_to_job(self.process.pid)
                    if not success:
                        print("Warning: Failed to assign Caddy process to job object")
            except Exception as e:
                print(f"Error creating job object: {e}")
            
            # Start a thread to capture output and write to log file
            def log_output():
                with open(self.log_file, 'a') as log:
                    while self.process and self.process.poll() is None:
                        # Read both stdout and stderr
                        stdout_line = self.process.stdout.readline()
                        stderr_line = self.process.stderr.readline()
                        
                        if stdout_line:
                            print(f"[STDOUT] {stdout_line}", end='')
                            log.write(f"{datetime.datetime.now().isoformat()}: [STDOUT] {stdout_line}")
                            log.flush()
                        if stderr_line:
                            print(f"[STDERR] {stderr_line}", end='')
                            log.write(f"{datetime.datetime.now().isoformat()}: [STDERR] {stderr_line}")
                            log.flush()
                            
                        if not stdout_line and not stderr_line:
                            time.sleep(0.1)
            
            threading.Thread(target=log_output, daemon=True).start()
            
            # Give Caddy more time to start and check if it's running
            time.sleep(5)
            
            # Check if process is still running after startup
            if self.process.poll() is not None:
                exitcode = self.process.poll()
                print(f"Caddy failed to start (exit code {exitcode})")
                
                # Try to read any error output
                try:
                    stdout_output = self.process.stdout.read()
                    stderr_output = self.process.stderr.read()
                    
                    if stdout_output:
                        print(f"Caddy stdout output: {stdout_output}")
                    if stderr_output:
                        print(f"Caddy stderr output: {stderr_output}")
                        
                    # Write the error output to the log file
                    with open(self.log_file, 'a') as log:
                        if stdout_output:
                            log.write(f"\nCaddy stdout output:\n{stdout_output}\n")
                        if stderr_output:
                            log.write(f"\nCaddy stderr output:\n{stderr_output}\n")
                except Exception as e:
                    print(f"Error reading Caddy output: {e}")
                    
                return False
                
            # Verify Caddy is actually running
            try:
                import psutil
                process = psutil.Process(self.process.pid)
                if not process.is_running():
                    print("Caddy process is not running")
                    return False
                
                # Additional check: verify Caddy is listening on the expected ports
                connections = process.connections()
                listening_ports = {conn.laddr.port for conn in connections if conn.status == 'LISTEN'}
                expected_ports = {80, 443, 9072}
                
                if not all(port in listening_ports for port in expected_ports):
                    print(f"Caddy is not listening on all expected ports. Listening on: {listening_ports}")
                    return False
                    
            except ImportError:
                print("psutil not installed, skipping process verification")
            except Exception as e:
                print(f"Error verifying Caddy process: {e}")
                
            print(f"Caddy started with PID {self.process.pid}")
            return True
            
        except Exception as e:
            print(f"Failed to start Caddy: {e}")
            return False

    def stop_caddy(self):
        """Stop the Caddy server if it's running"""
        if not self.process:
            return
            
        try:
            if self.process.poll() is None:
                # Try graceful termination first
                self.process.terminate()
                
                # Wait up to 3 seconds for graceful shutdown
                for _ in range(30):
                    if self.process.poll() is not None:
                        break
                    time.sleep(0.1)
                    
                # Force kill if still running
                if self.process.poll() is None:
                    self.process.kill()
                    
            self.logger.info("Caddy server stopped")
        except Exception as e:
            self.logger.error(f"Error stopping Caddy: {e}")
        finally:
            # Close the job handle if it exists
            if self.job_handle:
                kernel32.CloseHandle(self.job_handle)
                self.job_handle = None
            
            self.process = None

    def is_running(self):
        """Check if Caddy is currently running"""
        if not self.process:
            return False
            
        try:
            # Check if process is still running
            if self.process.poll() is not None:
                return False
                
            # Additional verification using psutil if available
            try:
                import psutil
                process = psutil.Process(self.process.pid)
                if not process.is_running():
                    return False
                    
                # Verify Caddy is listening on expected ports
                connections = process.connections()
                listening_ports = {conn.laddr.port for conn in connections if conn.status == 'LISTEN'}
                expected_ports = {80, 443, 9072}
                
                return all(port in listening_ports for port in expected_ports)
                
            except ImportError:
                # If psutil is not available, just check if process is running
                return True
            except Exception:
                return False
                
        except Exception:
            return False

# If run directly, test the Caddy manager
if __name__ == "__main__":
    manager = CaddyManager()
    
    # Example usage
    manager.generate_caddyfile("192.168.1.100", [80, 443], "127.0.0.1")
    if manager.start_caddy():
        print("Caddy started successfully. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping Caddy...")
        finally:
            manager.stop_caddy() 