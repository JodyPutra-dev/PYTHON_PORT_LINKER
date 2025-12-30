# PortLinker - A port forwarding and reverse proxy tool
# Copyright (c) 2025 Exp9072 (now JodyPutra-dev)
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
from cloudflare_tunnel_manager import CloudflareTunnelManager
from config import TRANSLATIONS, DEFAULT_PORTS, get_text, get_current_language, set_current_language, toggle_language
from core.network_utils import (
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
from core.firewall_manager import (
    check_firewall_status,
    check_firewall_rule_exists,
    add_firewall_rule,
    add_firewall_rules,
    delete_firewall_rule,
    delete_all_port_switcher_firewall_rules
)
from core.port_forwarding_service import PortForwardingService

# Initialize Cloudflare Tunnel Manager
cloudflare_manager = CloudflareTunnelManager()

# Initialize Port Forwarding Service
port_forwarding_service = PortForwardingService()



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
    QMessageBox.showerror("Error Admin", f"Terjadi error saat memeriksa hak admin:\n{str(e)}")
    sys.exit(1)



def stop_xampp():
    """Handle port conflicts with UI interactions, using utilities from core.network_utils."""
    active_ports = get_active_ports()
    ports_in_use = []
    
    # Check which ports are in use
    for port in active_ports:
        if check_port_in_use(port):
            ports_in_use.append(port)
    
    # If no ports in use, nothing to do
    if not ports_in_use:
        return True
        
    # Check if XAMPP is running
    xampp_detected = is_xampp_running()
        
    if not xampp_detected:
        # If XAMPP not running, inform user about port conflicts
        if ports_in_use:
            port_info = []
            pid_list = []
            
            for port in ports_in_use:
                process_info, pid = get_process_using_port(port)
                port_info.append(f"{port} (digunakan oleh {process_info})")
                if pid:
                    pid_list.append((port, pid, process_info))
                    
            ports_str = ", ".join(port_info)
            
            # If Python is using port, offer to kill the process
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
                if clicked_button == cancel_button:  # Cancel
                    return False
                elif clicked_button == yes_button:  # Yes - Kill process
                    for port, pid, _ in python_processes:
                        if kill_process_by_pid(pid):
                            QMessageBox.information(None, "Berhasil", f"Berhasil mematikan proses yang menggunakan port {port}")
                        else:
                            QMessageBox.warning(None, "Peringatan", f"Gagal mematikan proses yang menggunakan port {port}")
                    # Wait a bit for processes to end
                    time.sleep(1)
                # else: No - Continue
            else:
                # Regular non-Python processes
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
        
    # If we get here, XAMPP is running and needs to be stopped
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
        
    # Stop XAMPP services using utility function
    stop_xampp_services()
    
    # Wait a bit for processes to end
    time.sleep(1)
    
    # Check if we successfully freed the ports
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





def get_active_ports():
    """Get list of active ports from UI."""
    try:
        global ports_entry
        # Get from port text entry
        port_text = ports_entry.text().strip()
        return parse_port_string(port_text, DEFAULT_PORTS)
    except:
        return DEFAULT_PORTS

def process_port_selection(port_text):
    """Process port selection with UI error handling."""
    try:
        return parse_port_string(port_text, DEFAULT_PORTS)
    except ValueError as e:
        QMessageBox.warning(None, get_text("port_add_title"), str(e))
        return DEFAULT_PORTS

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
    ip = ip_entry.text().strip()
    listen_ip = listen_ip_entry.text().strip() or "0.0.0.0"
    
    if not ip:
        QMessageBox.critical(None, get_text("error_title"), get_text("error_no_target_ip"))
        return
    
    # Get active ports from UI
    active_ports = get_active_ports()
    if not active_ports:
        QMessageBox.critical(None, get_text("error_title"), get_text("error_no_ports"))
        return
        
    # Check if XAMPP is running and stop if needed (UI interaction)
    if not stop_xampp():
        # User cancelled or XAMPP couldn't be stopped
        return
    
    # Call the service to enable port forwarding
    result = port_forwarding_service.enable_forwarding(listen_ip, ip, active_ports)
    
    # Handle the result
    if not result["success"]:
        QMessageBox.critical(None, get_text("error_title"), 
                           result["error"] or "Failed to create port forwarding")
        return False
    
    # Handle firewall messages
    if result["firewall_active"]:
        failed_ports = result["failed_firewall_ports"]
        
        if result["firewall_success"] and not failed_ports:
            # All firewall rules added successfully
            port_list = ", ".join([str(p) for p in active_ports])
            QMessageBox.information(None, get_text("success_title"), 
                                  f"Firewall rules successfully added for ports: {port_list}")
        elif failed_ports:
            # Some firewall rules failed
            failed_list = ", ".join([str(p) for p in failed_ports])
            success_ports = [p for p in active_ports if p not in failed_ports]
            success_list = ", ".join([str(p) for p in success_ports])
            
            if get_current_language() == "en":
                msg = f"Warning: Failed to add firewall rules for ports: {failed_list}"
                if success_ports:
                    msg += f"\n\nSuccessfully added rules for: {success_list}"
            else:
                msg = f"Peringatan: Gagal menambahkan aturan firewall untuk port: {failed_list}"
                if success_ports:
                    msg += f"\n\nBerhasil menambahkan aturan untuk: {success_list}"
            
            QMessageBox.warning(None, get_text("warning_title") if get_current_language() == "en" else "Peringatan", msg)
        else:
            # All firewall rules failed
            if get_current_language() == "en":
                msg = "Failed to add any firewall rules. Port forwarding is active but may be blocked by firewall."
            else:
                msg = "Gagal menambahkan aturan firewall. Port forwarding aktif tetapi mungkin diblokir oleh firewall."
            QMessageBox.warning(None, get_text("warning_title") if get_current_language() == "en" else "Peringatan", msg)
    
    # Get network info from result
    hostname, ip_addresses, ipconfig = result["network_info"]
    if ip_addresses and len(ip_addresses) > 1:
        all_ips = "\n".join([f"- {ip}" for ip in ip_addresses[2]])
        if get_current_language() == "en":
            network_info = f"Your computer has the following IP addresses:\n{all_ips}\n\n" + \
                          "Make sure your phone is on the same network and try to access one of these IPs."
        else:
            network_info = f"Komputer Anda memiliki alamat IP berikut:\n{all_ips}\n\n" + \
                          "Pastikan ponsel Anda berada di jaringan yang sama dan coba akses salah satu IP ini."
    else:
        network_info = "Unable to retrieve network information." if get_current_language() == "en" else "Tidak dapat mengambil informasi jaringan."
    
    # Format port list for status display
    port_list_str = "/".join([str(p) for p in active_ports])
    
    # Update status label
    status_text = get_text("status_enabled", listen_ip=listen_ip, target_ip=ip, ports=port_list_str)
    status_label.setText(status_text)
    status_label.setStyleSheet("color: #10b981; font-weight: bold; padding: 5px;")
    
    # Show current rules
    show_current_rules()
    
    # Connection info dialog text
    if get_current_language() == "en":
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
    
    # Show network info dialog
    QMessageBox.information(None, connection_title, connection_text)
    
    return True
        
    return True

def start_cloudflare_tunnel():
    """Start Cloudflare Tunnel"""
    # Get IP and port from inputs
    ip = cf_tunnel_ip_entry.text().strip()
    port_text = cf_tunnel_port_entry.text().strip()
    
    # Validate IP
    if not ip:
        QMessageBox.critical(None, get_text("error_title"), get_text("cf_error_no_ip"))
        return
    
    # Validate port
    if not port_text:
        QMessageBox.critical(None, get_text("error_title"), get_text("cf_error_no_port"))
        return
    
    try:
        port = int(port_text)
        if port < 1 or port > 65535:
            raise ValueError()
    except ValueError:
        QMessageBox.critical(None, get_text("error_title"), get_text("cf_error_no_port"))
        return
    
    # Update status to starting
    cf_tunnel_status_label.setText(get_text("cf_status_starting"))
    cf_tunnel_status_label.setStyleSheet("font-weight: bold; padding: 10px; color: #f59e0b;")
    QApplication.processEvents()  # Force UI update
    
    # Start tunnel
    success = cloudflare_manager.start_tunnel(ip, port)
    
    if success:
        # Get tunnel URL
        tunnel_url = cloudflare_manager.get_tunnel_url()
        
        # Update status to running
        cf_tunnel_status_label.setText(get_text("cf_status_running"))
        cf_tunnel_status_label.setStyleSheet("font-weight: bold; padding: 10px; color: #10b981;")
        
        # Display URL
        if tunnel_url:
            cf_tunnel_url_text.setText(tunnel_url)
            cf_tunnel_url_text.setStyleSheet("color: #2563eb; font-weight: bold; padding: 5px;")
            cf_url_frame.setVisible(True)
            cf_copy_url_btn.setEnabled(True)
        
        # Update button states
        cf_start_btn.setEnabled(False)
        cf_stop_btn.setEnabled(True)
        
        # Show success message
        QMessageBox.information(None, get_text("success_title"), get_text("cf_success_started"))
    else:
        # Update status to stopped
        cf_tunnel_status_label.setText(get_text("cf_status_stopped"))
        cf_tunnel_status_label.setStyleSheet("font-weight: bold; padding: 10px; color: #64748b;")
        
        # Show error message
        QMessageBox.critical(None, get_text("error_title"), get_text("cf_error_start_failed"))

def stop_cloudflare_tunnel():
    """Stop Cloudflare Tunnel"""
    # Stop tunnel
    cloudflare_manager.stop_tunnel()
    
    # Update status
    cf_tunnel_status_label.setText(get_text("cf_status_stopped"))
    cf_tunnel_status_label.setStyleSheet("font-weight: bold; padding: 10px; color: #64748b;")
    
    # Clear URL
    cf_tunnel_url_text.setText("")
    cf_url_frame.setVisible(False)
    cf_copy_url_btn.setEnabled(False)
    
    # Update button states
    cf_start_btn.setEnabled(True)
    cf_stop_btn.setEnabled(False)
    
    # Show success message
    QMessageBox.information(None, get_text("success_title"), get_text("cf_success_stopped"))

def copy_tunnel_url():
    """Copy tunnel URL to clipboard"""
    url = cloudflare_manager.get_tunnel_url()
    if url:
        QApplication.clipboard().setText(url)
        QMessageBox.information(None, get_text("success_title"), get_text("cf_url_copied"))

def update_tunnel_status():
    """Periodic tunnel status check"""
    try:
        if cloudflare_manager.is_running():
            # Ensure UI reflects running state
            if cf_start_btn.isEnabled():
                cf_start_btn.setEnabled(False)
                cf_stop_btn.setEnabled(True)
                cf_tunnel_status_label.setText(get_text("cf_status_running"))
                cf_tunnel_status_label.setStyleSheet("font-weight: bold; padding: 10px; color: #10b981;")
                
                # Update URL if available
                url = cloudflare_manager.get_tunnel_url()
                if url and not cf_tunnel_url_text.text():
                    cf_tunnel_url_text.setText(url)
                    cf_tunnel_url_text.setStyleSheet("color: #2563eb; font-weight: bold; padding: 5px;")
                    cf_url_frame.setVisible(True)
                    cf_copy_url_btn.setEnabled(True)
        else:
            # Ensure UI reflects stopped state
            if cf_stop_btn.isEnabled():
                cf_start_btn.setEnabled(True)
                cf_stop_btn.setEnabled(False)
                cf_tunnel_status_label.setText(get_text("cf_status_stopped"))
                cf_tunnel_status_label.setStyleSheet("font-weight: bold; padding: 10px; color: #64748b;")
                cf_tunnel_url_text.setText("")
                cf_url_frame.setVisible(False)
                cf_copy_url_btn.setEnabled(False)
    except:
        pass  # Ignore errors in periodic check


        

def disable_port_forwarding():
    """Disable port forwarding"""
    try:
        # Get active ports from UI
        active_ports = get_active_ports()
        
        # Get specific listen IP
        listen_ip = listen_ip_entry.text().strip() or "0.0.0.0"
        
        # Determine whether to delete selected ports or all ports
        delete_all = False
        
        if active_ports:
            # Create message box with custom buttons
            msgbox = QMessageBox()
            
            if get_current_language() == "en":
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
            
            if clicked_button == yes_button:  # User clicked Yes - delete selected ports only
                delete_all = False
            elif clicked_button == no_button:  # User clicked No - delete all ports
                delete_all = True
        else:
            # No ports selected, ask to delete all
            msgbox = QMessageBox()
            
            if get_current_language() == "en":
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
                delete_all = True
        
        # Call the service to disable port forwarding
        result = port_forwarding_service.disable_forwarding(active_ports, listen_ip, delete_all)
        
        # Handle deletion errors
        if result["deletion_errors"]:
            print("Port deletion errors occurred:")
            for error in result["deletion_errors"]:
                print(f"- {error}")
        
        # Update status regardless of any possible errors
        status_label.setText(get_text("status_disabled"))
        status_label.setStyleSheet("color: #2563eb; font-weight: bold; padding: 5px;")
        
        # Clear and update rules display
        show_current_rules()
        
        QMessageBox.information(None, get_text("success_title"), get_text("success_disabled"))
        
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
    """Show current port forwarding rules"""
    try:
        # Call the service to get current rules
        success, result = port_forwarding_service.get_current_rules()
        
        # Update the rules text widget
        try:
            rules_text.setPlainText(result)
        except Exception as e:
            print(f"Error updating rules text widget: {e}")
            
    except Exception as e:
        print(f"Unexpected error in show_current_rules: {e}")
        try:
            rules_text.setPlainText(f"Error: {str(e)}")
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
    help_content = get_help_content_for_language(get_current_language())
    
    help_text.setHtml(help_content)
    help_container_layout.addWidget(help_text)
    
    scroll_area.setWidget(help_container)
    help_layout.addWidget(scroll_area)
    
    return help_tab

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

<h3>Panduan Instalasi Cloudflare Tunnel:</h3>
<p>Ikuti langkah-langkah berikut untuk menginstal Cloudflare Tunnel (cloudflared) di sistem Windows Anda:</p>

<ol>
    <li><b>Unduh cloudflared</b>
        <ul>
            <li>Kunjungi <a href="https://github.com/cloudflare/cloudflared/releases/latest" style="color: #2563eb;">halaman rilis GitHub resmi Cloudflare</a></li>
            <li>Unduh versi Windows: <span class="port">cloudflared-windows-amd64.exe</span></li>
        </ul>
    </li>

    <li><b>Ubah Nama dan Tempatkan File</b>
        <ul>
            <li>Ubah nama file yang diunduh menjadi <span class="port">cloudflared.exe</span></li>
            <li>Tempatkan di salah satu lokasi berikut:</li>
            <ul>
                <li>✓ Di folder yang sama dengan PortLinker.exe <span class="example">(metode termudah)</span></li>
                <li>Di folder khusus seperti <span class="port">C:\\Program Files\\cloudflared\\</span></li>
                <li>Di folder pengguna Anda: <span class="port">%LOCALAPPDATA%\\cloudflared\\</span></li>
            </ul>
        </ul>
    </li>

    <li><b>Tambahkan ke Windows PATH (Opsional tapi Disarankan)</b>
        <ul>
            <li>Untuk menggunakan cloudflared dari mana saja, tambahkan ke PATH sistem Anda:</li>
            <ol>
                <li>Klik kanan 'This PC' atau 'My Computer' dan pilih 'Properties'</li>
                <li>Klik 'Advanced system settings' → 'Environment Variables'</li>
                <li>Di bawah 'System variables', cari dan pilih 'Path', lalu klik 'Edit'</li>
                <li>Klik 'New' dan tambahkan path folder tempat Anda meletakkan cloudflared.exe</li>
                <li>Klik 'OK' pada semua dialog untuk menyimpan</li>
            </ol>
        </ul>
    </li>

    <li><b>Restart PortLinker</b>
        <ul>
            <li>Tutup dan buka kembali PortLinker</li>
            <li>Tab Cloudflare Tunnel sekarang harus diaktifkan</li>
        </ul>
    </li>

    <li><b>Verifikasi Instalasi</b>
        <ul>
            <li>Buka Command Prompt dan ketik: <span class="port">cloudflared --version</span></li>
            <li>Jika terinstal dengan benar, Anda akan melihat nomor versi</li>
        </ul>
    </li>
</ol>

<p><span class="highlight">Catatan:</span> Jika Anda meletakkan cloudflared.exe di folder yang sama dengan PortLinker, Anda tidak perlu menambahkannya ke PATH.</p>

<h3>Cloudflare Tunnel Installation Guide:</h3>
<p>Follow these steps to install Cloudflare Tunnel (cloudflared) on your Windows system:</p>

<ol>
    <li><b>Download cloudflared</b>
        <ul>
            <li>Visit the <a href="https://github.com/cloudflare/cloudflared/releases/latest" style="color: #2563eb;">official Cloudflare GitHub releases page</a></li>
            <li>Download the Windows version: <span class="port">cloudflared-windows-amd64.exe</span></li>
        </ul>
    </li>

    <li><b>Rename and Place the File</b>
        <ul>
            <li>Rename the downloaded file to <span class="port">cloudflared.exe</span></li>
            <li>Place it in one of these locations:</li>
            <ul>
                <li>✓ In the same folder as PortLinker.exe <span class="example">(easiest method)</span></li>
                <li>In a dedicated folder like <span class="port">C:\\Program Files\\cloudflared\\</span></li>
                <li>In your user folder: <span class="port">%LOCALAPPDATA%\\cloudflared\\</span></li>
            </ul>
        </ul>
    </li>

    <li><b>Add to Windows PATH (Optional but Recommended)</b>
        <ul>
            <li>To use cloudflared from anywhere, add it to your system PATH:</li>
            <ol>
                <li>Right-click 'This PC' or 'My Computer' and select 'Properties'</li>
                <li>Click 'Advanced system settings' → 'Environment Variables'</li>
                <li>Under 'System variables', find and select 'Path', then click 'Edit'</li>
                <li>Click 'New' and add the folder path where you placed cloudflared.exe</li>
                <li>Click 'OK' on all dialogs to save</li>
            </ol>
        </ul>
    </li>

    <li><b>Restart PortLinker</b>
        <ul>
            <li>Close and reopen PortLinker</li>
            <li>The Cloudflare Tunnel tab should now be enabled</li>
        </ul>
    </li>

    <li><b>Verify Installation</b>
        <ul>
            <li>Open Command Prompt and type: <span class="port">cloudflared --version</span></li>
            <li>If installed correctly, you'll see the version number</li>
        </ul>
    </li>
</ol>

<p><span class="highlight">Note:</span> If you placed cloudflared.exe in the same folder as PortLinker, you don't need to add it to PATH.</p>
</body>
</html>"""



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
        
        # Try to resolve hostname using utility function
        hostname = resolve_hostname(device["ip"], timeout_ms=500)
        if hostname:
            device["hostname"] = hostname
        
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
                if get_current_language() == "id":
                    resolve_btn.setText("Cari Batch Berikutnya")
                resolve_btn.setEnabled(True)
            else:
                # All done
                status_label.setText(f"Hostname resolution completed for {processed} devices.")
                
                # Reset resolve button text
                resolve_btn.setText("Resolve Hostnames")
                if get_current_language() == "id":
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
    if get_current_language() == "id":
        resolve_btn.setText("Cari Hostnames")
    resolve_btn.setEnabled(False)  # Initially disabled until we have devices
    button_layout.addWidget(resolve_btn)
    
    # Add cancel button for hostname resolution
    cancel_btn = QPushButton("Cancel")
    if get_current_language() == "id":
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
        self.setup_cloudflare_tab()
        
        # Create status bar
        self.statusBar().showMessage("Ready")
        
        # Create timer for tunnel status updates
        self.tunnel_status_timer = QTimer()
        self.tunnel_status_timer.timeout.connect(update_tunnel_status)
        self.tunnel_status_timer.start(2000)  # Check every 2 seconds
    
    def toggle_language(self):
        """Toggle between English and Indonesian languages"""
        # Switch language
        toggle_language()
        
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
        self.tabs.setTabText(2, get_text("tab_cloudflare"))
        
        # We need to recreate the tabs with new language
        current_tab = self.tabs.currentIndex()
        
        # Remove old tabs
        while self.tabs.count() > 0:
            self.tabs.removeTab(0)
        
        # Recreate tabs with new language
        self.setup_main_tab()
        self.setup_help_tab()
        self.setup_cloudflare_tab()
        
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
    
    def setup_cloudflare_tab(self):
        """Create the Cloudflare Tunnel tab"""
        global cf_tunnel_ip_entry, cf_tunnel_port_entry, cf_tunnel_status_label
        global cf_tunnel_url_text, cf_copy_url_btn, cf_url_frame
        global cf_start_btn, cf_stop_btn, cf_install_notice_label
        
        cloudflare_tab = QWidget()
        main_layout = QVBoxLayout(cloudflare_tab)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)
        
        # Info label
        info_label = QLabel(get_text("cf_info_text"))
        info_label.setWordWrap(True)
        info_label.setStyleSheet(
            "background-color: #dbeafe; padding: 15px; border-radius: 5px; "
            "color: #1e40af; border: 1px solid #93c5fd;"
        )
        main_layout.addWidget(info_label)
        
        # WSL Warning label
        wsl_warning_label = QLabel(get_text("cf_wsl_warning"))
        wsl_warning_label.setWordWrap(True)
        wsl_warning_label.setStyleSheet(
            "background-color: #fef3c7; padding: 12px; border-radius: 5px; "
            "color: #92400e; border: 1px solid #fbbf24; font-size: 11pt;"
        )
        main_layout.addWidget(wsl_warning_label)
        
        # Form section
        form_layout = QGridLayout()
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(10)
        form_layout.setColumnStretch(1, 1)
        
        # IP Address row
        ip_label = QLabel(get_text("cf_tunnel_ip_label"))
        form_layout.addWidget(ip_label, 0, 0)
        
        # Create horizontal layout for IP entry and detect button
        ip_widget = QWidget()
        ip_layout = QHBoxLayout(ip_widget)
        ip_layout.setContentsMargins(0, 0, 0, 0)
        ip_layout.setSpacing(10)
        
        cf_tunnel_ip_entry = QLineEdit()
        cf_tunnel_ip_entry.setMinimumWidth(250)
        # Set default value to Windows IP
        cf_tunnel_ip_entry.setText(get_local_ip())
        ip_layout.addWidget(cf_tunnel_ip_entry)
        
        # Add Detect IP button
        cf_detect_ip_btn = QPushButton(get_text("cf_detect_ip_btn"))
        cf_detect_ip_btn.setObjectName("detectButton")
        cf_detect_ip_btn.setMaximumWidth(100)
        cf_detect_ip_btn.clicked.connect(lambda: cf_tunnel_ip_entry.setText(get_local_ip()))
        ip_layout.addWidget(cf_detect_ip_btn)
        
        form_layout.addWidget(ip_widget, 0, 1)
        
        # Port row
        port_label = QLabel(get_text("cf_tunnel_port_label"))
        form_layout.addWidget(port_label, 1, 0)
        
        cf_tunnel_port_entry = QLineEdit()
        cf_tunnel_port_entry.setMinimumWidth(250)
        cf_tunnel_port_entry.setText("80")
        form_layout.addWidget(cf_tunnel_port_entry, 1, 1)
        
        main_layout.addLayout(form_layout)
        
        # Spacing
        main_layout.addSpacing(20)
        
        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        main_layout.addWidget(separator)
        
        # Spacing
        main_layout.addSpacing(20)
        
        # Button layout
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        cf_start_btn = QPushButton(get_text("cf_start_tunnel_btn"))
        cf_start_btn.setObjectName("enableButton")
        cf_start_btn.setMinimumHeight(40)
        cf_start_btn.clicked.connect(start_cloudflare_tunnel)
        button_layout.addWidget(cf_start_btn)
        
        cf_stop_btn = QPushButton(get_text("cf_stop_tunnel_btn"))
        cf_stop_btn.setObjectName("disableButton")
        cf_stop_btn.setMinimumHeight(40)
        cf_stop_btn.setEnabled(False)
        cf_stop_btn.clicked.connect(stop_cloudflare_tunnel)
        button_layout.addWidget(cf_stop_btn)
        
        # Check if cloudflared is installed
        is_installed = cloudflare_manager.is_cloudflared_installed()
        
        # If not installed, disable buttons
        if not is_installed:
            cf_start_btn.setEnabled(False)
            cf_stop_btn.setEnabled(False)
        
        main_layout.addLayout(button_layout)
        
        # Add installation notice label (shown only if not installed)
        cf_install_notice_label = QLabel()
        cf_install_notice_label.setWordWrap(True)
        cf_install_notice_label.setStyleSheet(
            "background-color: #fee2e2; padding: 12px; border-radius: 5px; "
            "color: #991b1b; border: 1px solid #fca5a5; font-size: 10pt;"
        )
        
        if not is_installed:
            notice_text = f"{get_text('cf_not_installed_notice')}\n{get_text('cf_install_guide_link')}"
            cf_install_notice_label.setText(notice_text)
            cf_install_notice_label.setVisible(True)
        else:
            cf_install_notice_label.setVisible(False)
        
        main_layout.addWidget(cf_install_notice_label)
        
        # Spacing
        main_layout.addSpacing(20)
        
        # Status label
        cf_tunnel_status_label = QLabel(get_text("cf_status_stopped"))
        cf_tunnel_status_label.setStyleSheet("font-weight: bold; padding: 10px; color: #64748b;")
        main_layout.addWidget(cf_tunnel_status_label)
        
        # Spacing
        main_layout.addSpacing(10)
        
        # URL display frame
        cf_url_frame = QFrame()
        cf_url_frame.setFrameShape(QFrame.StyledPanel)
        cf_url_frame.setStyleSheet("background-color: #f1f5f9; padding: 10px; border-radius: 5px;")
        url_layout = QVBoxLayout(cf_url_frame)
        url_layout.setContentsMargins(10, 10, 10, 10)
        url_layout.setSpacing(10)
        
        url_label = QLabel(get_text("cf_tunnel_url_label"))
        url_label.setStyleSheet("font-weight: bold;")
        url_layout.addWidget(url_label)
        
        cf_tunnel_url_text = QLabel("")
        cf_tunnel_url_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        cf_tunnel_url_text.setStyleSheet("color: #2563eb; font-weight: bold; padding: 5px;")
        url_layout.addWidget(cf_tunnel_url_text)
        
        cf_copy_url_btn = QPushButton(get_text("cf_copy_url_btn"))
        cf_copy_url_btn.setMinimumHeight(35)
        cf_copy_url_btn.setEnabled(False)
        cf_copy_url_btn.clicked.connect(copy_tunnel_url)
        url_layout.addWidget(cf_copy_url_btn)
        
        cf_url_frame.setVisible(False)  # Initially hidden
        main_layout.addWidget(cf_url_frame)
        
        # Add stretch to push everything to top
        main_layout.addStretch()
        
        # Add tab
        self.tabs.addTab(cloudflare_tab, get_text("tab_cloudflare"))
    
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

    # Override closeEvent to clean up
    def closeEvent(self, event):
        # Stop Cloudflare tunnel if running
        if cloudflare_manager.is_running():
            cloudflare_manager.stop_tunnel()
        # Call the parent class closeEvent
        super().closeEvent(event)

# Program utama
if __name__ == "__main__":
    try:
        # Check for language parameter
        if len(sys.argv) > 1 and sys.argv[1].lower() in ["--en", "--english", "-en"]:
            set_current_language("en")
        
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
            lang_param = " --en" if get_current_language() == "en" else ""
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
        error_title = "Fatal Error" if get_current_language() == "en" else "Error Fatal"
        error_content = f"An unexpected error occurred:\n\n{error_msg}" if get_current_language() == "en" else f"Terjadi error tak terduga:\n\n{error_msg}"
        QMessageBox.critical(None, error_title, error_content)
        sys.exit(1)
