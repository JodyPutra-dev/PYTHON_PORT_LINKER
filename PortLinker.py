# PortLinker - A port forwarding and reverse proxy tool
# Copyright (c) 2025 Exp9072
# Licensed under the MIT License. See the LICENSE file in the project root for full license information.

import sys
import subprocess
import ctypes
import os
import time
import socket
import traceback
import re
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, 
    QVBoxLayout, QHBoxLayout, QGridLayout, 
    QLabel, QPushButton, QLineEdit, QTextEdit, QFrame,
    QMessageBox, QInputDialog, QScrollArea, QDialog,
    QCheckBox, QGroupBox, QSizePolicy, QButtonGroup, QRadioButton, QComboBox
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QColor

# Import the Caddy Manager
from caddy_manager import CaddyManager

# Daftar port default
DEFAULT_PORTS = [80, 443, 9072]

# Caddy manager instance
caddy_manager = None

# Translation dictionary for multilingual support
TRANSLATIONS = {
    "en": {  # English
        "window_title": "PortLinker",
        "listen_ip_label": "Listen IP Address (Your PC's IP):",
        "target_ip_label": "Target IP Address (WSL IP):",
        "ports_label": "Ports (\"all\" means 80, 443, 9072):",
        "detect_ip_btn": "Detect IP",
        "add_port_tooltip": "Add port",
        "reset_ports_btn": "Reset",
        "enable_btn": "Enable Port Forwarding",
        "disable_btn": "Disable Port Forwarding",
        "refresh_btn": "Refresh Rules",
        "status_unknown": "Status: Unknown",
        "status_enabled": "Status: Port Forwarding Enabled\nForwarding {listen_ip}:{ports} → {target_ip}:{ports}",
        "status_disabled": "Status: Port Forwarding Disabled",
        "rules_header": "Current Port Proxy Rules:",
        "tab_forwarding": "Port Forwarding",
        "tab_troubleshoot": "Troubleshooting",
        "port_add_title": "Add Port",
        "port_add_prompt": "Enter port number:",
        "port_format_error": "Port must be a number: {part}",
        "port_range_error": "Invalid port range format: {part}",
        "error_title": "Error",
        "error_no_target_ip": "Please enter a valid target IP address.",
        "error_no_ports": "No ports selected for forwarding.",
        "error_add_port": "Failed to add port: {error}",
        "error_reset_port": "Failed to reset ports: {error}",
        "success_title": "Success",
        "success_disabled": "Port forwarding has been disabled",
        "network_dialog_title": "Network Information",
        "network_header": "Network Configuration Information",
        "hostname_label": "Hostname:",
        "ip_addresses_label": "IP Addresses:",
        "firewall_status_label": "Firewall Status:",
        "firewall_active": "Active",
        "firewall_inactive": "Inactive",
        "firewall_rules_label": "Firewall Rules for Port Forward:",
        "no_firewall_rules": "• No specific rules found for PortLinker",
        "active_ports_label": "Active Port Status:",
        "port_in_use": "In Use",
        "port_free": "Free",
        "close_btn": "Close",
        "app_not_ready": "Application is not ready to display network information.",
        "troubleshoot_header": "Troubleshooting Guide",
        "check_network_btn": "Check Network Configuration",
        "language_btn": "Switch to Indonesian",
        "connected_devices_label": "Connected Devices:",
        "device_ip_header": "IP Address",
        "device_mac_header": "MAC Address",
        "device_hostname_header": "Hostname",
        "refresh_devices_btn": "Refresh Devices",
        "show_devices_btn": "Show Connected Devices",
        "resolving_hostname": "Resolving...",
        "resolve_hostnames_btn": "Resolve Hostnames",
        "scanning_network": "Scanning network...",
        "cancel_btn": "Cancel",
        "https_enabled_label": "Enable HTTPS Reverse Proxy",
        "https_info_text": "HTTPS reverse proxy using Caddy with self-signed certificates.\nAccess your service securely via https://IP:PORT.\nBrowser warnings are normal with self-signed certificates.",
        "https_enabled": "HTTPS Reverse Proxy Enabled",
        "https_disabled": "HTTPS Reverse Proxy Disabled",
        "https_failed": "Failed to start HTTPS Reverse Proxy: {error}",
        "https_stop_failed": "Failed to stop HTTPS Reverse Proxy: {error}",
    },
    "id": {  # Indonesian
        "window_title": "PortLinker",
        "listen_ip_label": "Alamat IP Listen (IP PC Anda):",
        "target_ip_label": "Alamat IP Target (IP WSL):",
        "ports_label": "Port (\"all\" artinya 80, 443, 9072):",
        "detect_ip_btn": "Deteksi IP",
        "add_port_tooltip": "Tambah port",
        "reset_ports_btn": "Reset",
        "enable_btn": "Aktifkan Port Forwarding",
        "disable_btn": "Nonaktifkan Port Forwarding",
        "refresh_btn": "Refresh Aturan",
        "status_unknown": "Status: Tidak Diketahui",
        "status_enabled": "Status: Port Forwarding Diaktifkan\nForwarding {listen_ip}:{ports} → {target_ip}:{ports}",
        "status_disabled": "Status: Port Forwarding Dinonaktifkan",
        "rules_header": "Aturan Port Proxy Saat Ini:",
        "tab_forwarding": "Port Forwarding",
        "tab_troubleshoot": "Pemecahan Masalah",
        "port_add_title": "Tambah Port",
        "port_add_prompt": "Masukkan nomor port:",
        "port_format_error": "Port harus berupa angka: {part}",
        "port_range_error": "Format rentang port tidak valid: {part}",
        "error_title": "Error",
        "error_no_target_ip": "Silakan masukkan alamat IP target yang valid.",
        "error_no_ports": "Tidak ada port yang dipilih untuk forwarding.",
        "error_add_port": "Gagal menambahkan port: {error}",
        "error_reset_port": "Gagal mereset port: {error}",
        "success_title": "Berhasil",
        "success_disabled": "Port forwarding telah dinonaktifkan",
        "network_dialog_title": "Informasi Jaringan",
        "network_header": "Informasi Konfigurasi Jaringan",
        "hostname_label": "Hostname:",
        "ip_addresses_label": "Alamat IP:",
        "firewall_status_label": "Status Firewall:",
        "firewall_active": "Aktif",
        "firewall_inactive": "Tidak Aktif",
        "firewall_rules_label": "Aturan Firewall untuk Port Forward:",
        "no_firewall_rules": "• Tidak ditemukan aturan khusus untuk PortLinker",
        "active_ports_label": "Status Port Aktif:",
        "port_in_use": "Digunakan",
        "port_free": "Bebas",
        "close_btn": "Tutup",
        "app_not_ready": "Aplikasi belum siap untuk menampilkan informasi jaringan.",
        "troubleshoot_header": "Panduan Pemecahan Masalah",
        "check_network_btn": "Periksa Konfigurasi Jaringan",
        "language_btn": "Ganti ke Bahasa Inggris",
        "connected_devices_label": "Perangkat Terhubung:",
        "device_ip_header": "Alamat IP",
        "device_mac_header": "Alamat MAC",
        "device_hostname_header": "Hostname",
        "refresh_devices_btn": "Perbarui Perangkat",
        "show_devices_btn": "Tampilkan Perangkat Terhubung",
        "resolving_hostname": "Mencari...",
        "resolve_hostnames_btn": "Cari Hostnames",
        "scanning_network": "Memindai jaringan...",
        "cancel_btn": "Batal",
        "https_enabled_label": "Aktifkan HTTPS Reverse Proxy",
        "https_info_text": "HTTPS reverse proxy menggunakan Caddy dengan sertifikat self-signed.\nAkses layanan Anda dengan aman melalui https://IP:PORT.\nPeringatan browser normal dengan sertifikat self-signed.",
        "https_enabled": "HTTPS Reverse Proxy Diaktifkan",
        "https_disabled": "HTTPS Reverse Proxy Dinonaktifkan",
        "https_failed": "Gagal memulai HTTPS Reverse Proxy: {error}",
        "https_stop_failed": "Gagal menghentikan HTTPS Reverse Proxy: {error}",
    }
}

# Current language (default to Indonesian)
current_language = "id"

# Function to get translated text
def get_text(key, **kwargs):
    text = TRANSLATIONS[current_language].get(key, key)
    if kwargs:
        return text.format(**kwargs)
    return text

# Define application stylesheet
STYLESHEET = """
/* Main Colors:
   Primary: #2563eb (Blue)
   Secondary: #f8fafc (Light Gray)
   Dark: #1e293b (Dark Blue)
   Success: #10b981 (Green)
   Danger: #ef4444 (Red)
   Warning: #f59e0b (Amber)
   Info: #3b82f6 (Light Blue)
   Muted: #94a3b8 (Gray)
*/

QMainWindow, QDialog {
    background-color: #f8fafc;
}

QWidget {
    font-family: "Segoe UI", Arial, sans-serif;
    font-size: 10pt;
    color: #1e293b;
}

QTabWidget::pane {
    border: 1px solid #cbd5e1;
    border-top: 0px;
    background-color: #ffffff;
}

QTabBar::tab {
    background-color: #e2e8f0;
    border: 1px solid #cbd5e1;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    padding: 8px 16px;
    margin-right: 2px;
    color: #64748b;
}

QTabBar::tab:selected {
    background-color: #ffffff;
    color: #2563eb;
    font-weight: bold;
}

QTabBar::tab:hover:!selected {
    background-color: #f1f5f9;
    color: #334155;
}

QLabel {
    color: #334155;
}

QLineEdit {
    border: 1px solid #cbd5e1;
    border-radius: 4px;
    padding: 8px;
    background-color: #ffffff;
    selection-background-color: #2563eb;
    min-height: 14px;
}

QLineEdit:focus {
    border: 1px solid #2563eb;
}

QComboBox {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 4px;
    padding: 8px;
    min-height: 14px;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox::down-arrow {
    image: url(down_arrow.png);
    width: 12px;
    height: 12px;
}

QComboBox QAbstractItemView {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}

QPushButton {
    background-color: #2563eb;
    color: white;
    border: none;
    border-radius: 4px;
    padding: 8px 16px;
    font-weight: 500;
    min-height: 20px;
}

QPushButton:hover {
    background-color: #1d4ed8;
}

QPushButton:pressed {
    background-color: #1e40af;
}

QPushButton:disabled {
    background-color: #cbd5e1;
    color: #64748b;
}

QPushButton#addButton {
    padding: 4px 8px;
    font-weight: bold;
    background-color: #2563eb;
}

QPushButton#resetButton {
    background-color: #64748b;
}

QPushButton#resetButton:hover {
    background-color: #475569;
}

QPushButton#enableButton {
    background-color: #10b981;
}

QPushButton#enableButton:hover {
    background-color: #059669;
}

QPushButton#disableButton {
    background-color: #ef4444;
}

QPushButton#disableButton:hover {
    background-color: #dc2626;
}

QTextEdit {
    border: 1px solid #cbd5e1;
    border-radius: 4px;
    background-color: #ffffff;
    selection-background-color: #2563eb;
    font-family: "Consolas", "Courier New", monospace;
    padding: 8px;
}

QFrame[frameShape="4"] {  /* Horizontal lines */
    color: #e2e8f0;
    height: 1px;
}

QMessageBox {
    background-color: #ffffff;
}

QStatusBar {
    background-color: #f1f5f9;
    color: #475569;
    border-top: 1px solid #e2e8f0;
}

QScrollArea {
    background-color: transparent;
    border: none;
}

QScrollBar:vertical {
    border: none;
    background-color: #f1f5f9;
    width: 12px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background-color: #94a3b8;
    border-radius: 6px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background-color: #64748b;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    border: none;
    background-color: #f1f5f9;
    height: 12px;
    margin: 0px;
}

QScrollBar::handle:horizontal {
    background-color: #94a3b8;
    border-radius: 6px;
    min-width: 20px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #64748b;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

/* Frame styling for sections */
QFrame#sectionFrame {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
}
"""

def get_local_ip():
    """Dapatkan alamat IP lokal perangkat yang terhubung ke jaringan."""
    try:
        # Cara 1: Buat koneksi dummy untuk mendapatkan IP yang digunakan untuk komunikasi jaringan
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Alamat tidak perlu dapat dijangkau, ini hanya untuk mendapatkan antarmuka default
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        try:
            # Cara 2: Gunakan hostname jika cara 1 gagal
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            return local_ip
        except:
            try:
                # Cara 3: Periksa semua alamat IP yang terkait dengan hostname
                hostname = socket.gethostname()
                ip_addresses = socket.gethostbyname_ex(hostname)
                if ip_addresses and len(ip_addresses) > 1 and ip_addresses[2]:
                    # Pilih alamat IP non-localhost yang pertama
                    for ip in ip_addresses[2]:
                        if not ip.startswith("127."):
                            return ip
                    # Jika semuanya localhost, gunakan yang pertama
                    return ip_addresses[2][0]
            except:
                pass
    
    # Jika semua metode gagal, gunakan localhost sebagai fallback
    return "192.168.0.2"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Periksa admin privilege di awal
try:
    if not is_admin():
        # Jalankan ulang program dengan hak administrator
        script_path = os.path.abspath(sys.argv[0])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script_path}"', None, 1)
        sys.exit()
except Exception as e:
    # Tangkap error jika terjadi masalah dengan pemeriksaan admin
    messagebox.showerror("Error Admin", f"Terjadi error saat memeriksa hak admin:\n{str(e)}")
    sys.exit(1)

def check_port_in_use(port):
    """Periksa apakah port sedang digunakan oleh proses lain."""
    try:
        # Periksa apakah port sedang digunakan
        port_check = subprocess.run(
            ['netstat', '-ano', '|', 'findstr', f':{port}'], 
            shell=True, 
            capture_output=True, 
            text=True
        )
        return "LISTENING" in port_check.stdout
    except:
        return False

def kill_process_by_pid(pid):
    """Matikan proses berdasarkan PID."""
    try:
        subprocess.run(['taskkill', '/F', '/PID', str(pid)], 
                      shell=True, 
                      capture_output=True)
        return True
    except:
        return False

def get_process_using_port(port):
    """Mengidentifikasi proses yang menggunakan port tertentu."""
    try:
        # Dapatkan ID proses yang menggunakan port
        netstat_output = subprocess.run(
            ['netstat', '-ano', '|', 'findstr', f':{port}'], 
            shell=True, 
            capture_output=True, 
            text=True
        )
        
        if "LISTENING" not in netstat_output.stdout:
            return "Tidak ada proses", None
            
        # Ekstrak PID dari output netstat
        lines = netstat_output.stdout.strip().split('\n')
        for line in lines:
            if f':{port}' in line and 'LISTENING' in line:
                parts = line.strip().split()
                if len(parts) >= 5:
                    pid = parts[-1]
                    
                    # Dapatkan nama proses dari PID
                    tasklist_output = subprocess.run(
                        ['tasklist', '/FI', f'PID eq {pid}'], 
                        shell=True, 
                        capture_output=True, 
                        text=True
                    )
                    
                    # Ekstrak nama proses
                    if pid in tasklist_output.stdout:
                        process_line = [line for line in tasklist_output.stdout.split('\n') 
                                      if pid in line][0]
                        process_name = process_line.split()[0]
                        return f"{process_name} (PID: {pid})", pid
        
        return "Proses tidak dikenal", None
    except Exception as e:
        return f"Error mengidentifikasi proses: {str(e)}", None

def stop_xampp():
    active_ports = get_active_ports()
    ports_in_use = []
    
    # Periksa port mana yang sedang digunakan
    for port in active_ports:
        if check_port_in_use(port):
            ports_in_use.append(port)
    
    # Jika tidak ada port yang digunakan, tidak perlu melakukan apa-apa
    if not ports_in_use:
        return True
        
    # Coba identifikasi apakah XAMPP yang menggunakan port
    is_xampp = False
    try:
        # Periksa proses httpd.exe
        process_check = subprocess.run(
            ['tasklist', '|', 'findstr', 'httpd.exe'], 
            shell=True, 
            capture_output=True, 
            text=True
        )
        if 'httpd.exe' in process_check.stdout:
            is_xampp = True
    except:
        pass
        
    if not is_xampp:
        # Jika XAMPP tidak berjalan, hanya informasikan pengguna tentang konflik port
        if ports_in_use:
            port_info = []
            pid_list = []
            
            for port in ports_in_use:
                process_info, pid = get_process_using_port(port)
                port_info.append(f"{port} (digunakan oleh {process_info})")
                if pid:
                    pid_list.append((port, pid, process_info))
                    
            ports_str = ", ".join(port_info)
            
            # Jika Python menggunakan port, tawarkan untuk mematikan proses tersebut
            python_processes = [p for p in pid_list if "python" in p[2].lower()]
            
            if python_processes:
                # Create message box with custom buttons for Python processes
                msgbox = QMessageBox()
                msgbox.setWindowTitle("Python Menggunakan Port")
                msgbox.setText(f"Port {ports_str} digunakan oleh Python (kemungkinan aplikasi ini atau skrip Python lain).\n\n" +
                               "Apa yang ingin Anda lakukan?")
                msgbox.setInformativeText("- Yes: Matikan proses Python yang menggunakan port\n" +
                    "- No: Coba atur port forwarding tetap\n" +
                                         "- Cancel: Batalkan operasi")
                msgbox.setIcon(QMessageBox.Question)
                
                yes_button = msgbox.addButton("Yes", QMessageBox.YesRole)
                no_button = msgbox.addButton("No", QMessageBox.NoRole)
                cancel_button = msgbox.addButton("Cancel", QMessageBox.RejectRole)
                
                msgbox.exec()
                
                clicked_button = msgbox.clickedButton()
                if clicked_button == cancel_button:  # Batal
                    return False
                elif clicked_button == yes_button:  # Ya - Matikan proses
                    for port, pid, _ in python_processes:
                        if kill_process_by_pid(pid):
                            QMessageBox.information(None, "Berhasil", f"Berhasil mematikan proses yang menggunakan port {port}")
                        else:
                            QMessageBox.warning(None, "Peringatan", f"Gagal mematikan proses yang menggunakan port {port}")
                    # Tunggu sebentar agar proses berakhir
                    time.sleep(1)
                # else: Tidak - Lanjutkan
            else:
                # Proses non-Python biasa
                result = QMessageBox.question(
                    None,
                    "Konflik Port", 
                    f"Port berikut sudah digunakan oleh aplikasi lain:\n{ports_str}\n\n" +
                    "Apakah Anda ingin melanjutkan?\n\n" +
                    "Klik Yes untuk mencoba mengatur port forwarding tetap.\n" +
                    "Klik No untuk membatalkan.",
                    QMessageBox.Yes | QMessageBox.No
                )
                if result != QMessageBox.Yes:
                    return False
        return True
        
    # Jika kita sampai di sini, XAMPP sedang berjalan dan perlu dihentikan
    ports_list = ", ".join([str(p) for p in ports_in_use])
    result = QMessageBox.question(
        None,
        "XAMPP Berjalan", 
        f"XAMPP sepertinya sedang berjalan dan menggunakan port {ports_list}. " +
        "Apakah Anda ingin menghentikan XAMPP untuk melanjutkan?\n\n" +
        "Klik Yes untuk menghentikan XAMPP dan melanjutkan.\n" +
        "Klik No untuk membatalkan.",
        QMessageBox.Yes | QMessageBox.No
    )
    
    if result != QMessageBox.Yes:
        return False
        
    # Coba metode penghentian XAMPP umum
    xampp_paths = [
        r"C:\xampp\xampp_stop.exe",
        r"C:\xampp\xampp-control.exe",
    ]
    
    for path in xampp_paths:
        if os.path.exists(path):
            subprocess.run([path], 
                          shell=True, 
                          capture_output=True)
            time.sleep(1)  # Beri waktu untuk berhenti
            
    # Coba hentikan layanan Apache jika ada
    subprocess.run(
        ["net", "stop", "Apache2.4"], 
        shell=True, 
        capture_output=True
    )
    
    # Terakhir: Matikan semua proses Apache
    subprocess.run(
        ["taskkill", "/F", "/IM", "httpd.exe"], 
        shell=True, 
        capture_output=True
    )
    
    # Tunggu sebentar agar proses berakhir
    time.sleep(1)
    
    # Periksa apakah kita berhasil membebaskan port
    ports_still_in_use = []
    for port in ports_in_use:
        if check_port_in_use(port):
            ports_still_in_use.append(str(port))
            
    if ports_still_in_use:
        ports_list = ", ".join(ports_still_in_use)
        QMessageBox.warning(
            None,
            "Peringatan", 
            f"Tidak dapat membebaskan port: {ports_list}. Port forwarding mungkin tidak berfungsi dengan benar."
        )
        return False
        
    return True

def check_firewall_status():
    """Periksa status Windows Firewall dan apakah mungkin memblokir koneksi."""
    try:
        # Periksa status firewall
        firewall_check = subprocess.run(
            ['netsh', 'firewall', 'show', 'state'], 
            shell=True, 
            capture_output=True, 
            text=True
        )
        
        # Coba juga sintaks yang lebih baru
        firewall_check2 = subprocess.run(
            ['netsh', 'advfirewall', 'show', 'allprofiles'], 
            shell=True, 
            capture_output=True, 
            text=True
        )
        
        # Periksa apakah firewall aktif
        firewall_active = False
        
        if "ON" in firewall_check.stdout or "ON" in firewall_check2.stdout:
            firewall_active = True
            
        # Jika aktif, periksa apakah ada aturan untuk port kita
        port_rules = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all', '|', 'findstr', 'Port_Switcher'], 
            shell=True, 
            capture_output=True, 
            text=True
        )
        
        return (firewall_active, port_rules.stdout)
    except:
        return (False, "Error memeriksa status firewall")

def add_firewall_rules():
    """Tambahkan aturan firewall untuk mengizinkan koneksi masuk pada port yang dipilih."""
    try:
        ports = get_active_ports()
        
        for port in ports:
            rule_name = f"Port_Switcher_{port}"
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}', 'dir=in', 'action=allow',
                'protocol=TCP', f'localport={port}'
            ], shell=True, capture_output=True)
        
        return True
    except:
        return False

def get_network_info():
    """Dapatkan informasi jaringan untuk membantu mendiagnosis masalah koneksi."""
    try:
        # Dapatkan alamat IP
        hostname = socket.gethostname()
        ip_addresses = socket.gethostbyname_ex(hostname)
        
        # Dapatkan antarmuka jaringan aktif
        ipconfig = subprocess.run(
            ['ipconfig'], 
            shell=True, 
            capture_output=True, 
            text=True
        )
        
        return (hostname, ip_addresses, ipconfig.stdout)
    except Exception as e:
        return (None, None, str(e))

def get_active_ports():
    """Dapatkan daftar port yang aktif dari UI."""
    try:
        global ports_entry
        # Ambil dari entri teks port
        port_text = ports_entry.text().strip()
        return process_port_selection(port_text)
    except:
        return DEFAULT_PORTS

def process_port_selection(port_text):
    """
    Process a port selection string into a list of integer ports.
    Supports "all", individual ports, comma-separated lists, and ranges.
    
    Args:
        port_text (str): Text string containing port specifications
            
    Returns:
        list: List of integer port numbers
    """
    # If empty, use port default
    if not port_text:
        return DEFAULT_PORTS
        
    # If "all", use port default
    if port_text.lower() == "all":
        return DEFAULT_PORTS
        
    # Process string port
    port_list = []
    for part in port_text.split(','):
        part = part.strip()
        
        # Check if this is a port range (e.g., 8000-8005)
        if '-' in part:
            start, end = part.split('-')
            try:
                start_port = int(start.strip())
                end_port = int(end.strip())
                # Add all ports in the range
                port_list.extend(range(start_port, end_port + 1))
            except ValueError:
                QMessageBox.warning(None, get_text("port_add_title"), get_text("port_range_error", part=part))
        else:
            # Single port
            try:
                port_list.append(int(part))
            except ValueError:
                QMessageBox.warning(None, get_text("port_add_title"), get_text("port_format_error", part=part))
                
    # Remove duplicates
    port_list = list(set(port_list))
    
    # Validate
    if not port_list:
        return DEFAULT_PORTS
        
    return port_list

def add_port():
    """Tambahkan port baru ke daftar."""
    try:
        # Create custom dialog for adding port
        new_port, ok = QInputDialog.getInt(None, get_text("port_add_title"), get_text("port_add_prompt"), 80, 1, 65535)
        
        if ok and new_port > 0:
            current_ports = ports_entry.text().strip()
            if current_ports:
                if current_ports.lower() == "all":
                    # Mulai dari port default + port baru
                    new_ports = ','.join(map(str, DEFAULT_PORTS + [new_port]))
                else:
                    new_ports = current_ports + f", {new_port}"
            else:
                new_ports = str(new_port)
                
            ports_entry.setText(new_ports)
    except Exception as e:
        QMessageBox.critical(None, get_text("error_title"), get_text("error_add_port", error=str(e)))

def reset_ports():
    """Reset daftar port ke default."""
    try:
        ports_entry.setText("all")
    except Exception as e:
        QMessageBox.critical(None, get_text("error_title"), get_text("error_reset_port", error=str(e)))

def enable_port_forwarding():
    """Enable port forwarding"""
    global caddy_manager
    
    ip = ip_entry.text().strip()
    listen_ip = listen_ip_entry.text().strip() or "0.0.0.0"
    
    if not ip:
        QMessageBox.critical(None, get_text("error_title"), get_text("error_no_target_ip"))
        return
    
    # Dapatkan daftar port aktif menggunakan fungsi yang sudah ada
    active_ports = get_active_ports()
    if not active_ports:
        QMessageBox.critical(None, get_text("error_title"), get_text("error_no_ports"))
        return
        
    # Periksa apakah XAMPP sedang berjalan dan hentikan jika diperlukan
    if not stop_xampp():
        # Pengguna membatalkan atau XAMPP tidak dapat dihentikan
        return
    
    try:
        # Hapus aturan yang ada terlebih dahulu untuk port-port yang aktif
        for port in active_ports:
            subprocess.call([
                "netsh", "interface", "portproxy", "delete", 
                "v4tov4", f"listenport={port}", "listenaddress=0.0.0.0"
            ])
            
            # Juga coba hapus aturan untuk IP listen tertentu
            if listen_ip != "0.0.0.0":
                subprocess.call([
                    "netsh", "interface", "portproxy", "delete", 
                    "v4tov4", f"listenport={port}", f"listenaddress={listen_ip}"
                ])
        
        # Tambahkan aturan baru untuk setiap port
        for port in active_ports:
            # Jika listen_ip disediakan, tambahkan untuk IP tersebut
            if listen_ip != "0.0.0.0":
                subprocess.check_output([
                    "netsh", "interface", "portproxy", "add", "v4tov4",
                    f"listenport={port}", f"listenaddress={listen_ip}",
                    f"connectport={port}", f"connectaddress={ip}"
                ], stderr=subprocess.STDOUT)
            
            # Selalu tambahkan untuk semua antarmuka (0.0.0.0)
            subprocess.check_output([
                "netsh", "interface", "portproxy", "add", "v4tov4",
                f"listenport={port}", "listenaddress=0.0.0.0",
                f"connectport={port}", f"connectaddress={ip}"
            ], stderr=subprocess.STDOUT)

        # Periksa status firewall
        firewall_active, rules = check_firewall_status()
        if firewall_active:
            # Selalu tambahkan aturan firewall untuk semua port aktif
            for port in active_ports:
                rule_name = f"Port_Switcher_{port}"
                # Periksa apakah aturan sudah ada
                rule_check = subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name}'
                ], shell=True, capture_output=True, text=True)
                
                # Jika aturan belum ada, tambahkan
                if "No rules match the specified criteria" in rule_check.stdout or rule_check.returncode != 0:
                    subprocess.run([
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name={rule_name}', 'dir=in', 'action=allow',
                        'protocol=TCP', f'localport={port}'
                    ], shell=True, capture_output=True)
            
            # Tampilkan pesan sukses tentang aturan firewall
            port_list = ", ".join([str(p) for p in active_ports])
            QMessageBox.information(None, get_text("success_title"), f"Firewall rules successfully added for ports: {port_list}")
        
        # Check HTTPS mode and start Caddy if needed
        if https_mode_combo:
            selected_mode = https_mode_combo.currentText()
            if selected_mode in ["HTTPS Only", "Both HTTP and HTTPS"]:
                try:
                    # Initialize Caddy manager if needed
                    if caddy_manager is None:
                        caddy_manager = CaddyManager()
                    
                    # Generate Caddyfile and start Caddy
                    caddy_manager.generate_caddyfile(listen_ip, active_ports, ip)
                    success = caddy_manager.start_caddy()
                    
                    if success:
                        status_label.setText(f"{status_label.text()}\n{get_text('https_enabled')}")
                    else:
                        status_label.setText(f"{status_label.text()}\n{get_text('https_failed', error='Unknown error')}")
                except Exception as e:
                    status_label.setText(f"{status_label.text()}\n{get_text('https_failed', error=str(e))}")
        
        # Tampilkan info jaringan untuk membantu troubleshoot
        hostname, ip_addresses, ipconfig = get_network_info()
        if ip_addresses and len(ip_addresses) > 1:
            all_ips = "\n".join([f"- {ip}" for ip in ip_addresses[2]])
            if current_language == "en":
                network_info = f"Your computer has the following IP addresses:\n{all_ips}\n\n" + \
                              "Make sure your phone is on the same network and try to access one of these IPs."
            else:
                network_info = f"Komputer Anda memiliki alamat IP berikut:\n{all_ips}\n\n" + \
                              "Pastikan ponsel Anda berada di jaringan yang sama dan coba akses salah satu IP ini."
        else:
            network_info = "Unable to retrieve network information." if current_language == "en" else "Tidak dapat mengambil informasi jaringan."
        
        # Format daftar port untuk tampilan status
        port_list_str = "/".join([str(p) for p in active_ports])
        
        # Tampilkan status forwarding
        status_text = get_text("status_enabled", listen_ip=listen_ip, target_ip=ip, ports=port_list_str)
        status_label.setText(status_text)
        status_label.setStyleSheet("color: #10b981; font-weight: bold; padding: 5px;")
        
        # Tampilkan aturan saat ini
        show_current_rules()
        
        # Connection info dialog text
        if current_language == "en":
            connection_title = "Connection Info"
            connection_text = f"Port forwarding enabled:\n{listen_ip}:{port_list_str} → {ip}:{port_list_str}\n\n" + \
                            f"{network_info}\n\n" + \
                            "If you cannot connect from your phone, check:\n" + \
                            "1. Phone and PC are on the same network\n" + \
                            "2. Try using the IPs listed above\n" + \
                            "3. Windows Firewall may be blocking connections"
        else:
            connection_title = "Info Koneksi"
            connection_text = f"Port forwarding diaktifkan:\n{listen_ip}:{port_list_str} → {ip}:{port_list_str}\n\n" + \
                            f"{network_info}\n\n" + \
                            "Jika Anda tidak dapat terhubung dari ponsel, periksa:\n" + \
                            "1. Ponsel dan PC berada di jaringan yang sama\n" + \
                            "2. Coba gunakan IP yang tercantum di atas\n" + \
            "3. Windows Firewall mungkin memblokir koneksi"
        
        # Tampilkan info jaringan dalam dialog terpisah
        QMessageBox.information(
            None,
            connection_title, 
            connection_text
        )
    except subprocess.CalledProcessError as e:
        QMessageBox.critical(None, get_text("error_title"), f"Failed to create port forwarding: {e.output.decode('utf-8', errors='ignore')}")
        return False
    except Exception as e:
        QMessageBox.critical(None, get_text("error_title"), f"Failed to create port forwarding: {str(e)}")
        return False
        
    return True

def delete_all_port_switcher_firewall_rules():
    """Hapus semua aturan firewall yang dimulai dengan 'Port_Switcher_'."""
    try:
        # Gunakan PowerShell untuk menghapus aturan berdasarkan DisplayName
        try:
            powershell_cmd = 'powershell -Command "Get-NetFirewallRule | Where-Object { $_.DisplayName -like \'Port_Switcher_*\' } | Remove-NetFirewallRule -ErrorAction SilentlyContinue"'
            subprocess.run(powershell_cmd, shell=True, capture_output=True, timeout=10)
        except Exception as e:
            print(f"PowerShell method failed: {e}")
        
        # Alternatif dengan netsh (sebagai fallback)
        # Coba hapus aturan satu per satu menggunakan nama yang umum
        common_ports = [80, 443, 9072, 7760, 7761, 7762, 7763]
        for port in common_ports:
            try:
                rule_name = f"Port_Switcher_{port}"
                subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                    f'name={rule_name}'
                ], shell=True, capture_output=True, timeout=5)
            except Exception as e:
                print(f"Failed to delete rule for port {port}: {e}")
        
        # Sebagai upaya terakhir, coba dapatkan daftar semua aturan dan filter yang dimulai dengan Port_Switcher_
        try:
            firewall_rules = subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'
            ], shell=True, capture_output=True, text=True, timeout=10)
            
            if firewall_rules.returncode == 0 and firewall_rules.stdout:
                import re
                rule_names = re.findall(r'Rule Name:\s+(Port_Switcher_\d+)', firewall_rules.stdout)
                
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
        

def disable_port_forwarding():
    """Disable port forwarding"""
    global caddy_manager
    
    try:
        # Stop Caddy if it's running
        if caddy_manager and caddy_manager.is_running():
            try:
                caddy_manager.stop_caddy()
                status_label.setText(f"{get_text('status_disabled')}\n{get_text('https_disabled')}")
            except Exception as e:
                status_label.setText(f"{get_text('status_disabled')}\n{get_text('https_stop_failed', error=str(e))}")
        else:
            status_label.setText(get_text("status_disabled"))
        
        # Dapatkan port-port aktif menggunakan fungsi yang sudah ada
        active_ports = get_active_ports()
        
        # Dapatkan IP listen tertentu
        listen_ip = listen_ip_entry.text().strip() or "0.0.0.0"
        
        # Reset semua aturan (ini menghapus SEMUA port forwarding)
        if active_ports:
            # Create message box with custom buttons
            msgbox = QMessageBox()
            
            if current_language == "en":
                msgbox.setWindowTitle("Disable Port Forwarding")
                msgbox.setText("You can disable only selected ports or all existing port forwarding rules.\n\n")
                msgbox.setInformativeText("- Click Yes to remove ONLY selected ports\n- Click No to remove ALL port forwarding\n- Click Cancel to abort operation")
            else:
                msgbox.setWindowTitle("Nonaktifkan Port Forwarding")
                msgbox.setText("Anda dapat menonaktifkan hanya port yang dipilih atau semua port forwarding yang ada.\n\n")
                msgbox.setInformativeText("- Klik Yes untuk menghapus HANYA port yang dipilih\n- Klik No untuk menghapus SEMUA port forwarding\n- Klik Cancel untuk membatalkan operasi")
            
            msgbox.setIcon(QMessageBox.Question)
            
            yes_button = msgbox.addButton("Yes", QMessageBox.YesRole)
            no_button = msgbox.addButton("No", QMessageBox.NoRole)
            cancel_button = msgbox.addButton("Cancel", QMessageBox.RejectRole)
            
            msgbox.exec()
            
            clicked_button = msgbox.clickedButton()
            if clicked_button == cancel_button:  # User clicked Cancel
                return
            
            if clicked_button == yes_button:  # User clicked Yes
                # Hapus hanya port yang dipilih
                port_deletion_errors = []
                for port in active_ports:
                    # Hapus aturan dengan listen_ip tertentu
                    if listen_ip != "0.0.0.0":
                        try:
                            subprocess.run([
                                "netsh", "interface", "portproxy", "delete", 
                                "v4tov4", f"listenport={port}", f"listenaddress={listen_ip}"
                            ], check=False, capture_output=True, timeout=5)
                        except Exception as e:
                            port_deletion_errors.append(f"Failed to delete port {port} on IP {listen_ip}: {str(e)}")
                    
                    # Hapus aturan untuk semua antarmuka
                    try:
                        subprocess.run([
                            "netsh", "interface", "portproxy", "delete", 
                            "v4tov4", f"listenport={port}", "listenaddress=0.0.0.0"
                        ], check=False, capture_output=True, timeout=5)
                    except Exception as e:
                        port_deletion_errors.append(f"Failed to delete port {port} on IP 0.0.0.0: {str(e)}")
                        
                    # Hapus aturan firewall untuk port ini
                    try:
                        rule_name = f"Port_Switcher_{port}"
                        subprocess.run([
                            'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                            f'name={rule_name}'
                        ], shell=True, capture_output=True, timeout=5)
                    except Exception as e:
                        port_deletion_errors.append(f"Failed to delete firewall rule for port {port}: {str(e)}")
                        
                # Coba hapus aturan firewall yang mungkin masih tersisa
                try:
                    delete_all_port_switcher_firewall_rules()
                except Exception as e:
                    port_deletion_errors.append(f"Failed to delete all firewall rules: {str(e)}")
                    
                if port_deletion_errors:
                    print("Port deletion errors occurred:")
                    for error in port_deletion_errors:
                        print(f"- {error}")
            else:  # User clicked No - Hapus semua
                # Hapus SEMUA port forwarding dengan reset
                try:
                    subprocess.run([
                        "netsh", "interface", "portproxy", "reset"
                    ], check=False, capture_output=True, timeout=5)
                except Exception as e:
                    print(f"Failed to reset port proxy: {str(e)}")
                
                # Hapus SEMUA aturan firewall Port_Switcher
                try:
                    delete_all_port_switcher_firewall_rules()
                except Exception as e:
                    print(f"Failed to delete all firewall rules: {str(e)}")
        else:
            # Tidak ada port yang dipilih, hapus semua
            # Create message box with custom buttons
            msgbox = QMessageBox()
            
            if current_language == "en":
                msgbox.setWindowTitle("Disable Port Forwarding")
                msgbox.setText("You will delete ALL existing port forwarding rules.\n\n")
                msgbox.setInformativeText("- Click Yes to proceed\n- Click Cancel to abort operation")
            else:
                msgbox.setWindowTitle("Nonaktifkan Port Forwarding")
                msgbox.setText("Anda akan menghapus SEMUA port forwarding yang ada.\n\n")
                msgbox.setInformativeText("- Klik Yes untuk melanjutkan\n- Klik Cancel untuk membatalkan operasi")
            
            msgbox.setIcon(QMessageBox.Question)
            
            yes_button = msgbox.addButton("Yes", QMessageBox.YesRole)
            cancel_button = msgbox.addButton("Cancel", QMessageBox.RejectRole)
            
            msgbox.exec()
            
            if msgbox.clickedButton() == cancel_button:  # User clicked Cancel
                return
                
            if msgbox.clickedButton() == yes_button:  # User clicked Yes
                try:
                    subprocess.run([
                        "netsh", "interface", "portproxy", "reset"
                    ], check=False, capture_output=True, timeout=5)
                except Exception as e:
                    print(f"Failed to reset port proxy: {str(e)}")
                
                # Hapus SEMUA aturan firewall Port_Switcher
                try:
                    delete_all_port_switcher_firewall_rules()
                except Exception as e:
                    print(f"Failed to delete all firewall rules: {str(e)}")
        
        # Update status regardless of any possible errors above
        status_label.setText(get_text("status_disabled"))
        status_label.setStyleSheet("color: #2563eb; font-weight: bold; padding: 5px;")
        
        # Bersihkan dan perbarui tampilan aturan
        show_current_rules()
        
        QMessageBox.information(None, get_text("success_title"), get_text("success_disabled"))
    except Exception as e:
        print(f"Error updating UI after disabling port forwarding: {str(e)}")
            
    except Exception as e:
        print(f"Critical error in disable_port_forwarding: {str(e)}")
        # Try to show error message if possible
        try:
            QMessageBox.critical(None, get_text("error_title"), f"Failed to disable port forwarding: {str(e)}")
        except:
            print("Failed to show error messagebox")
        return False
    
    return True

def show_current_rules():
    try:
        # Dapatkan aturan portproxy saat ini
        result = subprocess.check_output(["netsh", "interface", "portproxy", "show", "all"], 
                                        stderr=subprocess.STDOUT, 
                                        universal_newlines=True,
                                        timeout=10)
        
        # Perbarui widget teks dengan aturan
        try:
            rules_text.setPlainText(result)
        except Exception as e:
            print(f"Error updating rules text widget: {e}")
            
    except subprocess.CalledProcessError as e:
        try:
            rules_text.setPlainText(f"Error mengambil aturan: {str(e)}")
        except Exception as ui_error:
            print(f"Error updating rules text widget after subprocess error: {ui_error}")
    except Exception as e:
        print(f"Unexpected error in show_current_rules: {e}")
        try:
            rules_text.setPlainText(f"Error tak terduga: {str(e)}")
        except:
            pass

def create_help_tab(notebook):
    """Buat tab bantuan dengan informasi pemecahan masalah."""
    help_tab = QWidget()
    help_layout = QVBoxLayout(help_tab)
    help_layout.setContentsMargins(15, 15, 15, 15)
    help_layout.setSpacing(15)
    
    # Create a styled header
    header = QLabel(get_text("troubleshoot_header"))
    header.setStyleSheet("font-size: 14pt; font-weight: bold; color: #2563eb; margin-bottom: 10px;")
    help_layout.addWidget(header)
    
    # Add button for connected devices
    devices_btn = QPushButton(get_text("show_devices_btn"))
    devices_btn.setMinimumHeight(40)
    devices_btn.clicked.connect(lambda: show_connected_devices_dialog(notebook))
    help_layout.addWidget(devices_btn)
    
    # Add button for network info with styling
    check_btn = QPushButton(get_text("check_network_btn"))
    check_btn.setMinimumHeight(40)
    check_btn.clicked.connect(lambda: show_network_info())
    help_layout.addWidget(check_btn)
    
    # Add button for HTTPS Reverse Proxy
    https_btn = QPushButton("HTTPS Reverse Proxy")
    https_btn.setMinimumHeight(40)
    https_btn.clicked.connect(lambda: show_https_reverse_proxy_dialog(notebook))
    help_layout.addWidget(https_btn)
    
    # Scroll area for help content
    scroll_area = QScrollArea()
    scroll_area.setWidgetResizable(True)
    scroll_area.setFrameShape(QFrame.NoFrame)
    scroll_area.setStyleSheet("background-color: transparent;")
    
    # Container for the help text
    help_container = QWidget()
    help_container.setObjectName("sectionFrame")
    help_container.setStyleSheet("background-color: #f1f1f1;")
    help_container_layout = QVBoxLayout(help_container)
    help_container_layout.setContentsMargins(15, 15, 15, 15)
    help_container_layout.setSpacing(0)
    
    help_text = QTextEdit()
    help_text.setReadOnly(True)
    help_text.setStyleSheet("""
        background-color: #ffffff;
        border: none;
        color: #1e293b;
        font-family: 'Segoe UI', Arial, sans-serif;
        font-size: 10pt;
        selection-background-color: #2563eb;
    """)
    
    # Add the help content - we'll use language-specific content
    help_content = get_help_content_for_language(current_language)
    
    help_text.setHtml(help_content)
    help_container_layout.addWidget(help_text)
    
    scroll_area.setWidget(help_container)
    help_layout.addWidget(scroll_area)
    
    return help_tab

def show_https_reverse_proxy_dialog(parent=None):
    """Show HTTPS Reverse Proxy configuration dialog"""
    if not parent and hasattr(app, 'window'):
        parent = app.window
    
    # Create dialog
    https_dialog = QDialog(parent)
    https_dialog.setWindowTitle("HTTPS Reverse Proxy")
    https_dialog.setMinimumSize(600, 400)
    
    # Create layout
    layout = QVBoxLayout(https_dialog)
    layout.setContentsMargins(15, 15, 15, 15)
    layout.setSpacing(15)
    
    # Add header
    header = QLabel("HTTPS Reverse Proxy Configuration")
    header.setStyleSheet("font-size: 14pt; font-weight: bold; color: #2563eb; margin-bottom: 10px;")
    layout.addWidget(header)
    
    # HTTPS Caddy section
    https_group = QGroupBox("HTTPS Reverse Proxy")
    https_layout = QVBoxLayout()
    https_layout.setContentsMargins(15, 15, 15, 15)
    https_layout.setSpacing(15)
    https_group.setLayout(https_layout)
    
    global https_checkbox
    https_checkbox = QCheckBox(get_text("https_enabled_label"))
    https_checkbox.setMinimumHeight(40)
    https_layout.addWidget(https_checkbox)
    
    https_info = QLabel(get_text("https_info_text"))
    https_info.setWordWrap(True)
    https_info.setMinimumHeight(80)
    https_info.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.MinimumExpanding)
    https_layout.addWidget(https_info)
    
    # Set minimum height for the entire group
    https_group.setMinimumHeight(150)
    layout.addWidget(https_group)
    
    # Add status label
    status_label = QLabel("Status: Not Configured")
    status_label.setStyleSheet("font-weight: bold; padding: 10px;")
    layout.addWidget(status_label)
    
    # Add buttons
    buttons_layout = QHBoxLayout()
    buttons_layout.setSpacing(10)
    
    # Add check Caddy button
    check_caddy_btn = QPushButton("Check Caddy Status")
    check_caddy_btn.setMinimumHeight(40)
    check_caddy_btn.clicked.connect(lambda: check_caddy_status(status_label))
    buttons_layout.addWidget(check_caddy_btn)
    
    # Add close button
    close_btn = QPushButton("Close")
    close_btn.setMinimumHeight(40)
    close_btn.clicked.connect(https_dialog.close)
    buttons_layout.addWidget(close_btn)
    
    layout.addLayout(buttons_layout)
    
    # Show the dialog
    https_dialog.exec()

def check_caddy_status(status_label):
    """Check the status of Caddy server"""
    global caddy_manager
    try:
        if caddy_manager and caddy_manager.is_running():
            status_label.setText("Status: Caddy is running")
            status_label.setStyleSheet("font-weight: bold; padding: 10px; color: #10b981;")
        else:
            status_label.setText("Status: Caddy is not running")
            status_label.setStyleSheet("font-weight: bold; padding: 10px; color: #ef4444;")
    except Exception as e:
        status_label.setText(f"Status: Error checking Caddy - {str(e)}")
        status_label.setStyleSheet("font-weight: bold; padding: 10px; color: #ef4444;")

def get_help_content_for_language(lang):
    """Get the appropriate help content HTML for the current language"""
    if lang == "en":
        return """<html>
<style>
    body { color: #1e293b; line-height: 1.6; background-color: #ffffff; }
    h3 { color: #2563eb; margin-top: 20px; margin-bottom: 10px; }
    li { margin-bottom: 8px; }
    ul { margin-top: 5px; }
    .port { color: #0d9488; font-family: monospace; }
    .highlight { color: #ef4444; font-weight: bold; }
    .example { color: #6d28d9; font-style: italic; }
</style>
<body>
<h3>Mobile Connection Troubleshooting:</h3>

<ol>
    <li><b>Ensure Both Devices Are on the Same Network</b>
        <ul>
            <li>Your phone and PC must be connected to the same WiFi network</li>
            <li>Home networks may isolate devices for security (check router settings)</li>
        </ul>
    </li>

    <li><b>Check Windows Firewall</b>
        <ul>
            <li>Windows Firewall may block incoming connections</li>
            <li>Temporarily disable Windows Firewall or add rules for the ports being used</li>
        </ul>
    </li>

    <li><b>Try Different IP Addresses</b>
        <ul>
            <li>Use IP addresses displayed in the Connection Info dialog</li>
            <li>Your PC may have multiple IP addresses - try each from your phone</li>
        </ul>
    </li>

    <li><b>Test Local Access First</b>
        <ul>
            <li>Before trying from your phone, verify http://localhost works on your PC</li>
            <li>Then try using the specific IP address in your PC browser</li>
        </ul>
    </li>

    <li><b>Router Settings</b>
        <ul>
            <li>Some routers block internal network requests by default</li>
            <li>Check if your router has AP isolation or client isolation enabled</li>
        </ul>
    </li>

    <li><b>Use the Correct Protocol and Port</b>
        <ul>
            <li>Use <span class="highlight">http://</span> (not https://) when connecting to port 80</li>
            <li>Include the port in the URL if using non-standard ports</li>
            <li>Example: <span class="example">http://192.168.0.2:9072</span></li>
        </ul>
    </li>

    <li><b>Port Format Information:</b>
        <ul>
            <li>Enter "<span class="port">all</span>" to use all default ports (80, 443, 9072)</li>
            <li>Enter a single port number, e.g.: <span class="port">8080</span></li>
            <li>Enter multiple ports separated by commas, e.g.: <span class="port">80, 443, 8080</span></li>
            <li>Enter a port range, e.g.: <span class="port">8000-8010</span></li>
            <li>Combination of the above: <span class="port">80, 443, 8000-8010, 9072</span></li>
        </ul>
    </li>
</ol>
</body>
</html>"""
    else:  # Indonesian (id)
        return """<html>
<style>
    body { color: #1e293b; line-height: 1.6; background-color: #ffffff; }
    h3 { color: #2563eb; margin-top: 20px; margin-bottom: 10px; }
    li { margin-bottom: 8px; }
    ul { margin-top: 5px; }
    .port { color: #0d9488; font-family: monospace; }
    .highlight { color: #ef4444; font-weight: bold; }
    .example { color: #6d28d9; font-style: italic; }
</style>
<body>
<h3>Pemecahan Masalah Koneksi Ponsel:</h3>

<ol>
    <li><b>Pastikan Kedua Perangkat Berada di Jaringan yang Sama</b>
        <ul>
            <li>Ponsel dan PC Anda harus terhubung ke jaringan WiFi yang sama</li>
            <li>Jaringan rumah mungkin mengisolasi perangkat untuk keamanan (periksa pengaturan router)</li>
        </ul>
    </li>

    <li><b>Periksa Windows Firewall</b>
        <ul>
            <li>Windows Firewall mungkin memblokir koneksi masuk</li>
            <li>Nonaktifkan Windows Firewall sementara atau tambahkan aturan untuk port yang digunakan</li>
        </ul>
    </li>

    <li><b>Coba Alamat IP yang Berbeda</b>
        <ul>
            <li>Gunakan alamat IP yang ditampilkan di dialog Info Koneksi</li>
            <li>PC Anda mungkin memiliki beberapa alamat IP - coba masing-masing dari ponsel Anda</li>
        </ul>
    </li>

    <li><b>Uji Akses Lokal Terlebih Dahulu</b>
        <ul>
            <li>Sebelum mencoba dari ponsel, verifikasi http://localhost berfungsi di PC Anda</li>
            <li>Kemudian coba gunakan alamat IP tertentu di browser PC</li>
        </ul>
    </li>

    <li><b>Pengaturan Router</b>
        <ul>
            <li>Beberapa router memblokir permintaan jaringan internal secara default</li>
            <li>Periksa apakah router Anda memiliki isolasi AP atau isolasi klien yang diaktifkan</li>
        </ul>
    </li>

    <li><b>Gunakan Protokol dan Port yang Benar</b>
        <ul>
            <li>Gunakan <span class="highlight">http://</span> (bukan https://) saat terhubung ke port 80</li>
            <li>Sertakan port di URL jika menggunakan port non-standar</li>
            <li>Contoh: <span class="example">http://192.168.0.2:9072</span></li>
        </ul>
    </li>

    <li><b>Informasi Format Port:</b>
        <ul>
            <li>Masukkan "<span class="port">all</span>" untuk menggunakan semua port default (80, 443, 9072)</li>
            <li>Masukkan nomor port tunggal, mis: <span class="port">8080</span></li>
            <li>Masukkan beberapa port dipisahkan koma, mis: <span class="port">80, 443, 8080</span></li>
            <li>Masukkan rentang port, mis: <span class="port">8000-8010</span></li>
            <li>Kombinasi dari format di atas: <span class="port">80, 443, 8000-8010, 9072</span></li>
        </ul>
    </li>
</ol>
</body>
</html>"""

def get_connected_devices():
    """Get a list of devices connected to the same network."""
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

def resolve_single_hostname(device, devices_table, status_label, current, batch_total, 
                           next_device_index, connected_devices, resolve_btn, cancel_btn,
                           remaining, total_count):
    """Resolve a single hostname and then process the next device."""
    # Check if we should stop (cancel button's property will be set to True if canceled)
    if cancel_btn.property("canceled") == True:
        # Mark all remaining devices as N/A (skip resolution)
        for i in range(next_device_index - 1, len(connected_devices)):
            if i < len(connected_devices) and not connected_devices[i].get("hostname", ""):
                connected_devices[i]["resolving"] = False
        
        # Update the table with all devices
        update_devices_table(connected_devices, devices_table)
        processed = current - 1
        status_label.setText(f"Hostname resolution cancelled. Completed {processed} of {total_count} devices.")
        resolve_btn.setEnabled(True)
        cancel_btn.setEnabled(False)
        return
        
    try:
        # Show current progress out of TOTAL devices, not just the current batch
        status_label.setText(f"Resolving hostname {current} of {batch_total} (total: {total_count})")
        QApplication.processEvents()
        
        # Try to resolve hostname with a quick timeout
        try:
            hostname_result = subprocess.run(
                ['ping', '-a', '-n', '1', '-w', '500', device["ip"]],  # 500ms timeout
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
                    hostname = hostname_match.group(1)
                    device["hostname"] = hostname
        except:
            pass  # Just skip on error
        
        # Clear resolving flag
        device["resolving"] = False
        
        # Update the table with the single device update
        update_devices_table(connected_devices, devices_table)
        
        # Process next device if there are more in this batch
        if next_device_index < batch_total:
            # Process next device after a small delay
            QTimer.singleShot(50, lambda: resolve_single_hostname(
                connected_devices[next_device_index], 
                devices_table, 
                status_label,
                current + 1, 
                batch_total,
                next_device_index + 1,
                connected_devices,
                resolve_btn,
                cancel_btn,
                remaining,
                total_count
            ))
        else:
            # This batch is done
            processed = min(batch_total, total_count)
            
            if remaining > 0:
                # If there are more devices to process, offer to continue
                status_label.setText(f"Completed {processed} of {total_count} devices. There are {remaining} more devices.")
                
                # Enable resolve button to process the next batch
                resolve_btn.setText("Resolve Next Batch")
                if current_language == "id":
                    resolve_btn.setText("Cari Batch Berikutnya")
                resolve_btn.setEnabled(True)
            else:
                # All done
                status_label.setText(f"Hostname resolution completed for {processed} devices.")
                
                # Reset resolve button text
                resolve_btn.setText("Resolve Hostnames")
                if current_language == "id":
                    resolve_btn.setText("Cari Hostnames")
                resolve_btn.setEnabled(True)
                
            cancel_btn.setEnabled(False)
            
    except Exception as e:
        print(f"Error resolving single hostname: {str(e)}")
        
        # Try to continue with next device if there are more in this batch
        if next_device_index < batch_total:
            QTimer.singleShot(50, lambda: resolve_single_hostname(
                connected_devices[next_device_index], 
                devices_table, 
                status_label,
                current + 1, 
                batch_total,
                next_device_index + 1,
                connected_devices,
                resolve_btn,
                cancel_btn,
                remaining,
                total_count
            ))
        else:
            resolve_btn.setEnabled(True)
            cancel_btn.setEnabled(False)

def resolve_hostnames_clicked(devices_table, status_label, resolve_btn, cancel_btn):
    """Handle click on resolve hostnames button"""
    try:
        # Get devices from the table property
        connected_devices = devices_table.property("devices")
        if not connected_devices:
            return
        
        # Count how many devices need resolution
        to_resolve = [d for d in connected_devices if not d.get("hostname")]
        if not to_resolve:
            status_label.setText("All hostnames already resolved.")
            return
            
        # Disable the button during resolution
        resolve_btn.setEnabled(False)
        
        # Reset and enable cancel button
        cancel_btn.setProperty("canceled", False)
        cancel_btn.setEnabled(True)
        
        # Only resolve a limited number of devices (max 15) to prevent hanging
        devices_to_resolve = to_resolve[:15]
        remaining = len(to_resolve) - 15
        
        # Show the TOTAL count, not just the ones we're resolving
        total_to_resolve = len(to_resolve)
        status_label.setText(f"Resolving hostnames for {len(devices_to_resolve)} out of {total_to_resolve} devices")
        if remaining > 0:
            status_label.setText(status_label.text() + f" ({remaining} will be processed in the next batch)")
        
        # Mark selected devices as resolving for UI feedback
        for device in devices_to_resolve:
            device["resolving"] = True
        
        # Update table to show "Resolving..." status
        update_devices_table(connected_devices, devices_table)
        
        # Need to process events to show the updated UI
        QApplication.processEvents()
        
        # Start resolving first device, which will chain to others
        if devices_to_resolve:
            QTimer.singleShot(100, lambda: resolve_single_hostname(
                devices_to_resolve[0],
                devices_table,
                status_label,
                1,
                len(devices_to_resolve),
                1,  # Start with second device next
                connected_devices,
                resolve_btn,
                cancel_btn,
                remaining,
                total_to_resolve
            ))
        
    except Exception as e:
        status_label.setText(f"Error resolving hostnames: {str(e)}")
        status_label.setStyleSheet("color: #ef4444;")
        resolve_btn.setEnabled(True)
        cancel_btn.setEnabled(False)
        print(f"Error in resolve_hostnames_clicked: {str(e)}")

def show_connected_devices_dialog(parent=None):
    """Show a dialog with only connected devices"""
    if not parent and hasattr(app, 'window'):
        parent = app.window
    
    # Create dialog first so we can show it while loading
    devices_dialog = QDialog(parent)
    devices_dialog.setWindowTitle(get_text("connected_devices_label"))
    devices_dialog.setMinimumSize(600, 400)
    
    # Create layout
    layout = QVBoxLayout(devices_dialog)
    layout.setContentsMargins(15, 15, 15, 15)
    layout.setSpacing(10)
    
    # Add header
    header = QLabel(get_text("connected_devices_label"))
    header.setStyleSheet("font-size: 14pt; font-weight: bold; color: #2563eb; margin-bottom: 10px;")
    layout.addWidget(header)
    
    # Create a status label for loading indication
    status_label = QLabel("Loading devices...")
    status_label.setStyleSheet("color: #4b5563; font-style: italic;")
    layout.addWidget(status_label)
    
    # Create a table for connected devices
    devices_table = QTextEdit()
    devices_table.setReadOnly(True)
    layout.addWidget(devices_table)
    
    # Button layout
    button_layout = QHBoxLayout()
    button_layout.setSpacing(10)
    
    # Add refresh button
    refresh_btn = QPushButton(get_text("refresh_devices_btn"))
    refresh_btn.clicked.connect(lambda: refresh_devices_dialog(devices_table, status_label, resolve_btn, cancel_btn))
    button_layout.addWidget(refresh_btn)
    
    # Add resolve hostnames button
    resolve_btn = QPushButton("Resolve Hostnames")
    if current_language == "id":
        resolve_btn.setText("Cari Hostnames")
    resolve_btn.setEnabled(False)  # Initially disabled until we have devices
    button_layout.addWidget(resolve_btn)
    
    # Add cancel button for hostname resolution
    cancel_btn = QPushButton("Cancel")
    if current_language == "id":
        cancel_btn.setText("Batal")
    cancel_btn.setEnabled(False)  # Initially disabled until resolving
    cancel_btn.setProperty("canceled", False)  # Property to track cancel state
    cancel_btn.clicked.connect(lambda: cancel_btn.setProperty("canceled", True))
    button_layout.addWidget(cancel_btn)
    
    # Connect resolve button now that we have cancel_btn
    resolve_btn.clicked.connect(lambda: resolve_hostnames_clicked(devices_table, status_label, resolve_btn, cancel_btn))
    
    # Add close button
    close_button = QPushButton(get_text("close_btn"))
    close_button.setMinimumHeight(35)
    close_button.clicked.connect(devices_dialog.close)
    button_layout.addWidget(close_button)
    
    layout.addLayout(button_layout)
    
    # Show the dialog immediately
    devices_dialog.show()
    
    # Start searching for devices (non-blocking)
    QTimer.singleShot(100, lambda: refresh_devices_dialog(devices_table, status_label, resolve_btn, cancel_btn))
    
    # Keep the dialog open
    devices_dialog.exec()

def refresh_devices_dialog(devices_table, status_label, resolve_btn, cancel_btn):
    """Refresh the devices table with loading indicator"""
    try:
        status_label.setText("Scanning network for devices...")
        status_label.setStyleSheet("color: #4b5563; font-style: italic;")
        devices_table.setHtml("<p>Scanning network...</p>")
        
        # Need to process events to show the loading message
        QApplication.processEvents()
        
        # Get devices
        connected_devices = get_connected_devices()
        
        if connected_devices:
            # Update table
            update_devices_table(connected_devices, devices_table)
            status_label.setText(f"Found {len(connected_devices)} devices. Use 'Resolve Hostnames' to get device names.")
            resolve_btn.setEnabled(True)
            
            # Store devices in the table for later use
            devices_table.setProperty("devices", connected_devices)
        else:
            devices_table.setHtml("<p>No devices found on network.</p>")
            status_label.setText("No devices found.")
            resolve_btn.setEnabled(False)
            
        # Reset and disable cancel button
        cancel_btn.setProperty("canceled", False)
        cancel_btn.setEnabled(False)
            
    except Exception as e:
        status_label.setText(f"Error scanning: {str(e)}")
        status_label.setStyleSheet("color: #ef4444;")
        print(f"Error in refresh_devices_dialog: {str(e)}")

def show_network_info(parent=None):
    """Show network information dialog based on parent"""
    if hasattr(app, 'window') and app.window:
        app.window.show_network_info()
    else:
        QMessageBox.information(None, get_text("network_dialog_title"), get_text("app_not_ready"))

def update_devices_table(connected_devices, devices_table):
    """Update the devices table with the current device list"""
    try:
        # Format the table
        table_html = "<table border='0' cellspacing='2' cellpadding='4' width='100%'>"
        table_html += "<tr style='background-color:#e2e8f0;'>"
        table_html += f"<th align='left'>{get_text('device_ip_header')}</th>"
        table_html += f"<th align='left'>{get_text('device_mac_header')}</th>"
        table_html += f"<th align='left'>{get_text('device_hostname_header')}</th>"
        table_html += "</tr>"
        
        for i, device in enumerate(connected_devices):
            bg_color = "#f1f5f9" if i % 2 == 1 else "#ffffff"
            table_html += f"<tr style='background-color:{bg_color};'>"
            table_html += f"<td>{device['ip']}</td>"
            table_html += f"<td>{device['mac']}</td>"
            
            hostname = device.get('hostname', '')
            if not hostname and device.get('resolving', False):
                hostname = "Resolving..."
            elif not hostname:
                hostname = "N/A"
                
            table_html += f"<td>{hostname}</td>"
            table_html += "</tr>"
        
        table_html += "</table>"
        devices_table.setHtml(table_html)
        
    except Exception as e:
        print(f"Error updating devices table: {str(e)}")
        devices_table.setHtml(f"<p>Error displaying devices: {str(e)}</p>")

# Create the main application class
class PortLinkerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Setup the main window
        self.setWindowTitle(get_text("window_title"))
        self.setMinimumSize(750, 900)  # Increased minimum height
        self.resize(800, 1000)  # Increased default size
        
        # Get local IP
        self.local_ip = get_local_ip()
        
        # Create the central widget and main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Create language switcher button
        self.language_btn = QPushButton(get_text("language_btn"))
        self.language_btn.clicked.connect(self.toggle_language)
        self.language_btn.setMaximumWidth(200)
        self.main_layout.addWidget(self.language_btn, 0, Qt.AlignRight)
        
        # Create tabs
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        # Setup tabs
        self.setup_main_tab()
        self.setup_help_tab()
        
        # Create status bar
        self.statusBar().showMessage("Ready")
    
    def toggle_language(self):
        """Toggle between English and Indonesian languages"""
        global current_language
        # Switch language
        current_language = "en" if current_language == "id" else "id"
        
        # Update UI text
        self.update_ui_language()
    
    def update_ui_language(self):
        """Update all UI elements with the current language"""
        # Update window title
        self.setWindowTitle(get_text("window_title"))
        
        # Update language button
        self.language_btn.setText(get_text("language_btn"))
        
        # Update tab names
        self.tabs.setTabText(0, get_text("tab_forwarding"))
        self.tabs.setTabText(1, get_text("tab_troubleshoot"))
        
        # Update HTTPS checkbox
        if https_checkbox:
            https_checkbox.setText(get_text("https_enabled_label"))
        
        # We need to recreate the tabs with new language
        current_tab = self.tabs.currentIndex()
        
        # Remove old tabs
        while self.tabs.count() > 0:
            self.tabs.removeTab(0)
        
        # Recreate tabs with new language
        self.setup_main_tab()
        self.setup_help_tab()
        
        # Restore current tab
        self.tabs.setCurrentIndex(current_tab)
    
    def setup_main_tab(self):
        """Create the main port forwarding tab"""
        main_tab = QWidget()
        main_layout = QVBoxLayout(main_tab)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)
        
        # Create form layout for settings
        form_layout = QGridLayout()
        form_layout.setVerticalSpacing(15)
        form_layout.setHorizontalSpacing(15)
        main_layout.addLayout(form_layout)
        
        # Listen IP section
        listen_ip_label = QLabel(get_text("listen_ip_label"))
        form_layout.addWidget(listen_ip_label, 0, 0)
        
        listen_ip_widget = QWidget()
        listen_ip_layout = QHBoxLayout(listen_ip_widget)
        listen_ip_layout.setContentsMargins(0, 0, 0, 0)
        listen_ip_layout.setSpacing(10)
        form_layout.addWidget(listen_ip_widget, 0, 1)
        
        global listen_ip_entry
        listen_ip_entry = QLineEdit()
        listen_ip_entry.setText(self.local_ip)
        listen_ip_entry.setMinimumWidth(250)
        listen_ip_layout.addWidget(listen_ip_entry)
        
        detect_ip_btn = QPushButton(get_text("detect_ip_btn"))
        detect_ip_btn.clicked.connect(self.detect_ip)
        listen_ip_layout.addWidget(detect_ip_btn)
        
        # Target IP section
        target_ip_label = QLabel(get_text("target_ip_label"))
        form_layout.addWidget(target_ip_label, 1, 0)
        
        global ip_entry
        ip_entry = QLineEdit()
        ip_entry.setText("172.29.156.41")  # Default WSL IP
        ip_entry.setMinimumWidth(250)
        form_layout.addWidget(ip_entry, 1, 1)
        
        # Ports section
        ports_label = QLabel(get_text("ports_label"))
        form_layout.addWidget(ports_label, 2, 0)
        
        ports_widget = QWidget()
        ports_layout = QHBoxLayout(ports_widget)
        ports_layout.setContentsMargins(0, 0, 0, 0)
        ports_layout.setSpacing(10)
        form_layout.addWidget(ports_widget, 2, 1)
        
        global ports_entry
        ports_entry = QLineEdit()
        ports_entry.setText("all")
        ports_entry.setMinimumWidth(250)
        ports_layout.addWidget(ports_entry)
        
        add_port_btn = QPushButton("+")
        add_port_btn.setObjectName("addButton")
        add_port_btn.setMaximumWidth(30)
        add_port_btn.setToolTip(get_text("add_port_tooltip"))
        add_port_btn.clicked.connect(add_port)
        ports_layout.addWidget(add_port_btn)
        
        reset_ports_btn = QPushButton(get_text("reset_ports_btn"))
        reset_ports_btn.setObjectName("resetButton")
        reset_ports_btn.setMaximumWidth(60)
        reset_ports_btn.clicked.connect(reset_ports)
        ports_layout.addWidget(reset_ports_btn)
        
        # HTTPS Configuration section
        https_label = QLabel("Protocol Mode:")
        form_layout.addWidget(https_label, 3, 0)
        
        https_widget = QWidget()
        https_layout = QHBoxLayout(https_widget)
        https_layout.setContentsMargins(0, 0, 0, 0)
        https_layout.setSpacing(10)
        form_layout.addWidget(https_widget, 3, 1)
        
        global https_mode_combo
        https_mode_combo = QComboBox()
        https_mode_combo.addItems(["HTTP Only", "HTTPS Only", "Both HTTP and HTTPS"])
        https_mode_combo.setMinimumWidth(250)
        https_layout.addWidget(https_mode_combo)
        
        # Add info text
        https_info = QLabel("HTTPS requires Caddy to be running")
        https_info.setStyleSheet("color: #64748b; font-style: italic;")
        https_layout.addWidget(https_info)
        
        # Add spacing after the form
        main_layout.addSpacing(20)
        
        # Create a separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        main_layout.addWidget(separator)
        
        # Add spacing after separator
        main_layout.addSpacing(20)
        
        # Action buttons
        buttons_layout = QVBoxLayout()
        buttons_layout.setSpacing(15)
        main_layout.addLayout(buttons_layout)
        
        enable_btn = QPushButton(get_text("enable_btn"))
        enable_btn.setObjectName("enableButton")
        enable_btn.setMinimumHeight(40)
        enable_btn.clicked.connect(enable_port_forwarding)
        buttons_layout.addWidget(enable_btn)
        
        disable_btn = QPushButton(get_text("disable_btn"))
        disable_btn.setObjectName("disableButton")
        disable_btn.setMinimumHeight(40)
        disable_btn.clicked.connect(disable_port_forwarding)
        buttons_layout.addWidget(disable_btn)
        
        refresh_btn = QPushButton(get_text("refresh_btn"))
        refresh_btn.setMinimumHeight(40)
        refresh_btn.clicked.connect(show_current_rules)
        buttons_layout.addWidget(refresh_btn)
        
        # Add spacing after buttons
        main_layout.addSpacing(20)
        
        # Status label with styling
        global status_label
        status_label = QLabel(get_text("status_unknown"))
        status_label.setStyleSheet("font-weight: bold; padding: 10px;")
        main_layout.addWidget(status_label)
        
        # Add spacing after status
        main_layout.addSpacing(20)
        
        # Rules section - with a nice header
        rules_header = QLabel(get_text("rules_header"))
        rules_header.setStyleSheet("font-weight: bold; font-size: 12pt; color: #1e293b; margin-top: 10px; margin-bottom: 10px;")
        main_layout.addWidget(rules_header)
        
        # Rules text area with a nice border
        global rules_text
        rules_text = QTextEdit()
        rules_text.setReadOnly(True)
        rules_text.setMinimumHeight(200)
        rules_text.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        rules_text.setLineWrapMode(QTextEdit.NoWrap)
        main_layout.addWidget(rules_text, 1)
        
        # Add the main tab to tabs
        self.tabs.addTab(main_tab, get_text("tab_forwarding"))
        
        # Initialize the current rules display
        show_current_rules()
        
    def setup_help_tab(self):
        """Create the help tab"""
        help_tab = create_help_tab(self.tabs)
        self.tabs.addTab(help_tab, get_text("tab_troubleshoot"))
    
    def detect_ip(self):
        """Detect and update local IP address"""
        listen_ip_entry.setText(get_local_ip())
    
    def show_network_info(self):
        """Show network information dialog"""
        hostname, ip_addresses, ipconfig = get_network_info()
        
        # Create dialog
        network_dialog = QDialog(self)
        network_dialog.setWindowTitle(get_text("network_dialog_title"))
        network_dialog.setMinimumSize(700, 500)
        
        # Create layout
        layout = QVBoxLayout(network_dialog)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        
        # Add header
        header = QLabel(get_text("network_header"))
        header.setStyleSheet("font-size: 14pt; font-weight: bold; color: #2563eb; margin-bottom: 10px;")
        layout.addWidget(header)
        
        # Create sections container
        sections = QWidget()
        sections_layout = QVBoxLayout(sections)
        sections_layout.setContentsMargins(0, 0, 0, 0)
        sections_layout.setSpacing(15)
        
        # Hostname section
        if hostname:
            host_frame = QFrame()
            host_frame.setObjectName("sectionFrame")
            host_frame.setFrameShape(QFrame.StyledPanel)
            host_layout = QVBoxLayout(host_frame)
            
            host_label = QLabel(get_text("hostname_label"))
            host_label.setStyleSheet("font-weight: bold;")
            host_layout.addWidget(host_label)
            
            host_value = QLabel(hostname)
            host_layout.addWidget(host_value)
            
            sections_layout.addWidget(host_frame)
        
        # IP Addresses section
        if ip_addresses and len(ip_addresses) > 1:
            ip_frame = QFrame()
            ip_frame.setObjectName("sectionFrame")
            ip_frame.setFrameShape(QFrame.StyledPanel)
            ip_layout = QVBoxLayout(ip_frame)
            
            ip_label = QLabel(get_text("ip_addresses_label"))
            ip_label.setStyleSheet("font-weight: bold;")
            ip_layout.addWidget(ip_label)
            
            for ip in ip_addresses[2]:
                ip_value = QLabel(f"• {ip}")
                ip_layout.addWidget(ip_value)
            
            sections_layout.addWidget(ip_frame)
        
        # Firewall section
        firewall_active, rules = check_firewall_status()
        
        firewall_frame = QFrame()
        firewall_frame.setObjectName("sectionFrame")
        firewall_frame.setFrameShape(QFrame.StyledPanel)
        firewall_layout = QVBoxLayout(firewall_frame)
        
        firewall_header = QLabel(get_text("firewall_status_label"))
        firewall_header.setStyleSheet("font-weight: bold;")
        firewall_layout.addWidget(firewall_header)
        
        active_text = get_text("firewall_active") if firewall_active else get_text("firewall_inactive")
        firewall_status = QLabel(f"• {active_text}")
        firewall_status.setStyleSheet(f"color: {'#ef4444' if firewall_active else '#10b981'};")
        firewall_layout.addWidget(firewall_status)
        
        if rules and "Port_Switcher" in rules:
            rule_label = QLabel(get_text("firewall_rules_label"))
            rule_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
            firewall_layout.addWidget(rule_label)
            
            rules_text_edit = QTextEdit()
            rules_text_edit.setReadOnly(True)
            rules_text_edit.setMaximumHeight(100)
            rules_text_edit.setText(rules)
            firewall_layout.addWidget(rules_text_edit)
        else:
            no_rules = QLabel(get_text("no_firewall_rules"))
            firewall_layout.addWidget(no_rules)
        
        sections_layout.addWidget(firewall_frame)
        
        # Active ports section
        ports_frame = QFrame()
        ports_frame.setObjectName("sectionFrame")
        ports_frame.setFrameShape(QFrame.StyledPanel)
        ports_layout = QVBoxLayout(ports_frame)
        
        ports_label = QLabel(get_text("active_ports_label"))
        ports_label.setStyleSheet("font-weight: bold;")
        ports_layout.addWidget(ports_label)
        
        active_ports = get_active_ports()
        for port in active_ports:
            is_used = check_port_in_use(port)
            status = get_text("port_in_use") if is_used else get_text("port_free")
            color = "#ef4444" if is_used else "#10b981"
            
            port_status = QLabel(f"• Port {port}: {status}")
            port_status.setStyleSheet(f"color: {color};")
            ports_layout.addWidget(port_status)
        
        sections_layout.addWidget(ports_frame)
        
        # Scrollable area for all sections
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(sections)
        layout.addWidget(scroll_area)
        
        # Close button
        close_button = QPushButton(get_text("close_btn"))
        close_button.setMinimumHeight(35)
        close_button.clicked.connect(network_dialog.close)
        layout.addWidget(close_button)
        
        # Show the dialog
        network_dialog.exec()

    # Override closeEvent to clean up Caddy
    def closeEvent(self, event):
        global caddy_manager
        # Stop Caddy if it's running
        if caddy_manager and caddy_manager.is_running():
            try:
                caddy_manager.stop_caddy()
            except:
                pass
        # Call the parent class closeEvent
        super().closeEvent(event)

# Program utama
if __name__ == "__main__":
    try:
        # Check for language parameter
        if len(sys.argv) > 1 and sys.argv[1].lower() in ["--en", "--english", "-en"]:
            current_language = "en"
        
        # Create the application
        app = QApplication(sys.argv)
        
        # Set application style
        app.setStyle("Fusion")
        
        # Apply the custom stylesheet
        app.setStyleSheet(STYLESHEET)
        
        # Check admin privileges first
        if not is_admin():
            # Rerun the program with admin rights and preserve language choice
            script_path = os.path.abspath(sys.argv[0])
            lang_param = " --en" if current_language == "en" else ""
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script_path}"{lang_param}', None, 1)
            sys.exit()
        
        # Create and show the main window
        app.window = PortLinkerApp()
        app.window.show()
        
        # Start the event loop
        sys.exit(app.exec())
        
    except Exception as e:
        # Tangkap semua error agar program tidak langsung tertutup
        error_msg = traceback.format_exc()
        error_title = "Fatal Error" if current_language == "en" else "Error Fatal"
        error_content = f"An unexpected error occurred:\n\n{error_msg}" if current_language == "en" else f"Terjadi error tak terduga:\n\n{error_msg}"
        QMessageBox.critical(None, error_title, error_content)
        sys.exit(1)
