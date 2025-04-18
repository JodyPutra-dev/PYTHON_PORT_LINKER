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
    QMessageBox, QInputDialog, QScrollArea, QDialog
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QColor

# Daftar port default
DEFAULT_PORTS = [80, 443, 9072]

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
                QMessageBox.warning(None, "Format Port", f"Format rentang port tidak valid: {part}")
        else:
            # Single port
            try:
                port_list.append(int(part))
            except ValueError:
                QMessageBox.warning(None, "Format Port", f"Port harus berupa angka: {part}")
                
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
        new_port, ok = QInputDialog.getInt(None, "Tambah Port", "Masukkan nomor port:", 80, 1, 65535)
        
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
        QMessageBox.critical(None, "Error", f"Gagal menambahkan port: {str(e)}")

def reset_ports():
    """Reset daftar port ke default."""
    try:
        ports_entry.setText("all")
    except Exception as e:
        QMessageBox.critical(None, "Error", f"Gagal mereset port: {str(e)}")

def enable_port_forwarding():
    """Enable port forwarding"""
    ip = ip_entry.text().strip()
    listen_ip = listen_ip_entry.text().strip() or "0.0.0.0"
    
    if not ip:
        QMessageBox.critical(None, "Error", "Silakan masukkan alamat IP target yang valid.")
        return
    
    # Dapatkan daftar port aktif menggunakan fungsi yang sudah ada
    active_ports = get_active_ports()
    if not active_ports:
        QMessageBox.critical(None, "Error", "Tidak ada port yang dipilih untuk forwarding.")
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
            QMessageBox.information(None, "Firewall Diatur", f"Aturan firewall berhasil ditambahkan untuk port: {port_list}")
        
        # Tampilkan info jaringan untuk membantu troubleshoot
        hostname, ip_addresses, ipconfig = get_network_info()
        if ip_addresses and len(ip_addresses) > 1:
            all_ips = "\n".join([f"- {ip}" for ip in ip_addresses[2]])
            network_info = f"Komputer Anda memiliki alamat IP berikut:\n{all_ips}\n\n" + \
                          "Pastikan ponsel Anda berada di jaringan yang sama dan coba akses salah satu IP ini."
        else:
            network_info = "Tidak dapat mengambil informasi jaringan."
        
        # Format daftar port untuk tampilan status
        port_list_str = "/".join([str(p) for p in active_ports])
        
        # Tampilkan status forwarding
        status_text = f"Status: Port Forwarding Diaktifkan\nForwarding {listen_ip}:{port_list_str} → {ip}:{port_list_str}"
        status_label.setText(status_text)
        status_label.setStyleSheet("color: #10b981; font-weight: bold; padding: 5px;")
        
        # Tampilkan aturan saat ini
        show_current_rules()
        
        # Tampilkan info jaringan dalam dialog terpisah
        QMessageBox.information(
            None,
            "Info Koneksi", 
            f"Port forwarding diaktifkan:\n{listen_ip}:{port_list_str} → {ip}:{port_list_str}\n\n" +
            f"{network_info}\n\n" +
            "Jika Anda tidak dapat terhubung dari ponsel, periksa:\n" +
            "1. Ponsel dan PC berada di jaringan yang sama\n" +
            "2. Coba gunakan IP yang tercantum di atas\n" +
            "3. Windows Firewall mungkin memblokir koneksi"
        )
    except subprocess.CalledProcessError as e:
        QMessageBox.critical(None, "Error", f"Gagal membuat port forwarding: {e.output.decode('utf-8', errors='ignore')}")
        return False
    except Exception as e:
        QMessageBox.critical(None, "Error", f"Gagal membuat port forwarding: {str(e)}")
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
    try:
        # Dapatkan port-port aktif menggunakan fungsi yang sudah ada
        active_ports = get_active_ports()
        
        # Dapatkan IP listen tertentu
        listen_ip = listen_ip_entry.text().strip() or "0.0.0.0"
        
        # Reset semua aturan (ini menghapus SEMUA port forwarding)
        if active_ports:
            # Create message box with custom buttons
            msgbox = QMessageBox()
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
        try:
            status_label.setText("Status: Port Forwarding Dinonaktifkan")
            status_label.setStyleSheet("color: #2563eb; font-weight: bold; padding: 5px;")
            
            # Bersihkan dan perbarui tampilan aturan
            show_current_rules()
            
            QMessageBox.information(None, "Berhasil", "Port forwarding telah dinonaktifkan")
        except Exception as e:
            print(f"Error updating UI after disabling port forwarding: {str(e)}")
            
    except Exception as e:
        print(f"Critical error in disable_port_forwarding: {str(e)}")
        # Try to show error message if possible
        try:
            QMessageBox.critical(None, "Error", f"Gagal menonaktifkan port forwarding: {str(e)}")
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
    header = QLabel("Panduan Pemecahan Masalah")
    header.setStyleSheet("font-size: 14pt; font-weight: bold; color: #2563eb; margin-bottom: 10px;")
    help_layout.addWidget(header)
    
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
    
    # Add the help content
    help_content = """<html>
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
    
    help_text.setHtml(help_content)
    help_container_layout.addWidget(help_text)
    
    scroll_area.setWidget(help_container)
    help_layout.addWidget(scroll_area)
    
    # Add button for network info with styling
    check_btn = QPushButton("Periksa Konfigurasi Jaringan")
    check_btn.setMinimumHeight(40)
    check_btn.clicked.connect(show_network_info)
    help_layout.addWidget(check_btn)
    
    return help_tab

def show_network_info(self):
    """Show network information dialog"""
    hostname, ip_addresses, ipconfig = get_network_info()
    
    # Create dialog
    network_dialog = QDialog(self)
    network_dialog.setWindowTitle("Informasi Jaringan")
    network_dialog.setMinimumSize(700, 500)
    
    # Create layout
    layout = QVBoxLayout(network_dialog)
    layout.setContentsMargins(15, 15, 15, 15)
    layout.setSpacing(10)
    
    # Add header
    header = QLabel("Informasi Konfigurasi Jaringan")
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
        
        host_label = QLabel("Hostname:")
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
        
        ip_label = QLabel("Alamat IP:")
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
    
    firewall_header = QLabel("Status Firewall:")
    firewall_header.setStyleSheet("font-weight: bold;")
    firewall_layout.addWidget(firewall_header)
    
    firewall_status = QLabel(f"• {'Aktif' if firewall_active else 'Tidak Aktif'}")
    firewall_status.setStyleSheet(f"color: {'#ef4444' if firewall_active else '#10b981'};")
    firewall_layout.addWidget(firewall_status)
    
    if rules and "Port_Switcher" in rules:
        rule_label = QLabel("Aturan Firewall untuk Port Forward:")
        rule_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        firewall_layout.addWidget(rule_label)
        
        rules_text_edit = QTextEdit()
        rules_text_edit.setReadOnly(True)
        rules_text_edit.setMaximumHeight(100)
        rules_text_edit.setText(rules)
        firewall_layout.addWidget(rules_text_edit)
    else:
        no_rules = QLabel("• Tidak ditemukan aturan khusus untuk PortLinker")
        firewall_layout.addWidget(no_rules)
    
    sections_layout.addWidget(firewall_frame)
    
    # Active ports section
    ports_frame = QFrame()
    ports_frame.setObjectName("sectionFrame")
    ports_frame.setFrameShape(QFrame.StyledPanel)
    ports_layout = QVBoxLayout(ports_frame)
    
    ports_label = QLabel("Status Port Aktif:")
    ports_label.setStyleSheet("font-weight: bold;")
    ports_layout.addWidget(ports_label)
    
    active_ports = get_active_ports()
    for port in active_ports:
        is_used = check_port_in_use(port)
        status = "Digunakan" if is_used else "Bebas"
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
    close_button = QPushButton("Tutup")
    close_button.setMinimumHeight(35)
    close_button.clicked.connect(network_dialog.close)
    layout.addWidget(close_button)
    
    # Show the dialog
    network_dialog.exec()

# Fixed show_network_info function
def show_network_info(parent=None):
    """Show network information dialog based on parent"""
    if hasattr(app, 'window') and app.window:
        app.window.show_network_info()
    else:
        QMessageBox.information(None, "Info", "Aplikasi belum siap untuk menampilkan informasi jaringan.")

# For compatibility with messagebox functions used in the original code
def show_messagebox(title, message, icon=QMessageBox.Information, buttons=QMessageBox.Ok):
    msg = QMessageBox()
    msg.setWindowTitle(title)
    msg.setText(message)
    msg.setIcon(icon)
    msg.setStandardButtons(buttons)
    return msg.exec()

# Override original functions
def messagebox_showinfo(title, message):
    return show_messagebox(title, message, QMessageBox.Information)

def messagebox_showwarning(title, message):
    return show_messagebox(title, message, QMessageBox.Warning)

def messagebox_showerror(title, message):
    return show_messagebox(title, message, QMessageBox.Critical)

def messagebox_askyesno(title, message):
    result = show_messagebox(title, message, QMessageBox.Question, QMessageBox.Yes | QMessageBox.No)
    return result == QMessageBox.Yes

def messagebox_askyesnocancel(title, message):
    msgbox = QMessageBox()
    msgbox.setWindowTitle(title)
    msgbox.setText(message)
    msgbox.setIcon(QMessageBox.Question)
    
    yes_button = msgbox.addButton("Yes", QMessageBox.YesRole)
    no_button = msgbox.addButton("No", QMessageBox.NoRole)
    cancel_button = msgbox.addButton("Cancel", QMessageBox.RejectRole)
    
    result = msgbox.exec()
    
    if msgbox.clickedButton() == yes_button:
        return True
    elif msgbox.clickedButton() == no_button:
        return False
    else:  # Cancel
        return None

# Create compatibility layer for original code
messagebox = type('messagebox', (), {
    'showinfo': messagebox_showinfo,
    'showwarning': messagebox_showwarning,
    'showerror': messagebox_showerror,
    'askyesno': messagebox_askyesno,
    'askyesnocancel': messagebox_askyesnocancel,
})

# Create the main application class
class PortLinkerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Setup the main window
        self.setWindowTitle("PortLinker")
        self.setMinimumSize(750, 650)
        
        # Get local IP
        self.local_ip = get_local_ip()
        
        # Create the central widget and main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Create tabs
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        # Setup tabs
        self.setup_main_tab()
        self.setup_help_tab()
        
        # Create status bar
        self.statusBar().showMessage("Ready")
    
    def setup_main_tab(self):
        """Create the main port forwarding tab"""
        main_tab = QWidget()
        main_layout = QVBoxLayout(main_tab)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)
        
        # Create form layout for settings
        form_layout = QGridLayout()
        form_layout.setVerticalSpacing(15)
        form_layout.setHorizontalSpacing(15)
        main_layout.addLayout(form_layout)
        
        # Listen IP section
        listen_ip_label = QLabel("Alamat IP Listen (IP PC Anda):")
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
        
        detect_ip_btn = QPushButton("Deteksi IP")
        detect_ip_btn.clicked.connect(self.detect_ip)
        listen_ip_layout.addWidget(detect_ip_btn)
        
        # Target IP section
        target_ip_label = QLabel("Alamat IP Target (IP WSL):")
        form_layout.addWidget(target_ip_label, 1, 0)
        
        global ip_entry
        ip_entry = QLineEdit()
        ip_entry.setText("172.29.156.41")  # Default WSL IP
        ip_entry.setMinimumWidth(250)
        form_layout.addWidget(ip_entry, 1, 1)
        
        # Ports section
        ports_label = QLabel("Port (all artinya 80, 443, 9072):")
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
        add_port_btn.clicked.connect(add_port)
        ports_layout.addWidget(add_port_btn)
        
        reset_ports_btn = QPushButton("Reset")
        reset_ports_btn.setObjectName("resetButton")
        reset_ports_btn.setMaximumWidth(60)
        reset_ports_btn.clicked.connect(reset_ports)
        ports_layout.addWidget(reset_ports_btn)
        
        # Add some spacing
        main_layout.addSpacing(10)
        
        # Create a separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        main_layout.addWidget(separator)
        
        main_layout.addSpacing(10)
        
        # Action buttons
        buttons_layout = QVBoxLayout()
        buttons_layout.setSpacing(10)
        main_layout.addLayout(buttons_layout)
        
        enable_btn = QPushButton("Aktifkan Port Forwarding")
        enable_btn.setObjectName("enableButton")
        enable_btn.clicked.connect(enable_port_forwarding)
        buttons_layout.addWidget(enable_btn)
        
        disable_btn = QPushButton("Nonaktifkan Port Forwarding")
        disable_btn.setObjectName("disableButton")
        disable_btn.clicked.connect(disable_port_forwarding)
        buttons_layout.addWidget(disable_btn)
        
        refresh_btn = QPushButton("Refresh Aturan")
        refresh_btn.clicked.connect(show_current_rules)
        buttons_layout.addWidget(refresh_btn)
        
        main_layout.addSpacing(10)
        
        # Status label with styling
        global status_label
        status_label = QLabel("Status: Tidak Diketahui")
        status_label.setStyleSheet("font-weight: bold; padding: 5px;")
        main_layout.addWidget(status_label)
        
        # Rules section - with a nice header
        rules_header = QLabel("Aturan Port Proxy Saat Ini:")
        rules_header.setStyleSheet("font-weight: bold; font-size: 12pt; color: #1e293b; margin-top: 10px;")
        main_layout.addWidget(rules_header)
        
        # Rules text area with a nice border
        global rules_text
        rules_text = QTextEdit()
        rules_text.setReadOnly(True)
        rules_text.setMinimumHeight(200)
        rules_text.setLineWrapMode(QTextEdit.NoWrap)  # Better for displaying command output
        main_layout.addWidget(rules_text)
        
        # Add the main tab to tabs
        self.tabs.addTab(main_tab, "Port Forwarding")
        
        # Initialize the current rules display
        show_current_rules()
    
    def setup_help_tab(self):
        """Create the help tab"""
        help_tab = create_help_tab(self.tabs)
        self.tabs.addTab(help_tab, "Pemecahan Masalah")
    
    def detect_ip(self):
        """Detect and update local IP address"""
        listen_ip_entry.setText(get_local_ip())
    
    def show_network_info(self):
        """Show network information dialog"""
        hostname, ip_addresses, ipconfig = get_network_info()
        
        # Create dialog
        network_dialog = QDialog(self)
        network_dialog.setWindowTitle("Informasi Jaringan")
        network_dialog.setMinimumSize(700, 500)
        
        # Create layout
        layout = QVBoxLayout(network_dialog)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        
        # Add header
        header = QLabel("Informasi Konfigurasi Jaringan")
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
            
            host_label = QLabel("Hostname:")
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
            
            ip_label = QLabel("Alamat IP:")
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
        
        firewall_header = QLabel("Status Firewall:")
        firewall_header.setStyleSheet("font-weight: bold;")
        firewall_layout.addWidget(firewall_header)
        
        firewall_status = QLabel(f"• {'Aktif' if firewall_active else 'Tidak Aktif'}")
        firewall_status.setStyleSheet(f"color: {'#ef4444' if firewall_active else '#10b981'};")
        firewall_layout.addWidget(firewall_status)
        
        if rules and "Port_Switcher" in rules:
            rule_label = QLabel("Aturan Firewall untuk Port Forward:")
            rule_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
            firewall_layout.addWidget(rule_label)
            
            rules_text_edit = QTextEdit()
            rules_text_edit.setReadOnly(True)
            rules_text_edit.setMaximumHeight(100)
            rules_text_edit.setText(rules)
            firewall_layout.addWidget(rules_text_edit)
        else:
            no_rules = QLabel("• Tidak ditemukan aturan khusus untuk PortLinker")
            firewall_layout.addWidget(no_rules)
        
        sections_layout.addWidget(firewall_frame)
        
        # Active ports section
        ports_frame = QFrame()
        ports_frame.setObjectName("sectionFrame")
        ports_frame.setFrameShape(QFrame.StyledPanel)
        ports_layout = QVBoxLayout(ports_frame)
        
        ports_label = QLabel("Status Port Aktif:")
        ports_label.setStyleSheet("font-weight: bold;")
        ports_layout.addWidget(ports_label)
        
        active_ports = get_active_ports()
        for port in active_ports:
            is_used = check_port_in_use(port)
            status = "Digunakan" if is_used else "Bebas"
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
        close_button = QPushButton("Tutup")
        close_button.setMinimumHeight(35)
        close_button.clicked.connect(network_dialog.close)
        layout.addWidget(close_button)
        
        # Show the dialog
        network_dialog.exec()

# Fixed show_network_info function
def show_network_info(parent=None):
    """Show network information dialog based on parent"""
    if hasattr(app, 'window') and app.window:
        app.window.show_network_info()
    else:
        QMessageBox.information(None, "Info", "Aplikasi belum siap untuk menampilkan informasi jaringan.")

# Program utama
if __name__ == "__main__":
    try:
        # Create the application
        app = QApplication(sys.argv)
        
        # Set application style
        app.setStyle("Fusion")
        
        # Apply the custom stylesheet
        app.setStyleSheet(STYLESHEET)
        
        # Check admin privileges first
        if not is_admin():
            # Rerun the program with admin rights
            script_path = os.path.abspath(sys.argv[0])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script_path}"', None, 1)
            sys.exit()
        
        # Create and show the main window
        app.window = PortLinkerApp()
        app.window.show()
        
        # Start the event loop
        sys.exit(app.exec())
        
    except Exception as e:
        # Tangkap semua error agar program tidak langsung tertutup
        error_msg = traceback.format_exc()
        QMessageBox.critical(None, "Error Fatal", f"Terjadi error tak terduga:\n\n{error_msg}")
        sys.exit(1)
