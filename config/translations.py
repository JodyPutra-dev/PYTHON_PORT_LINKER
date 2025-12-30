# PortLinker - A port forwarding and reverse proxy tool
# Copyright (c) 2025 Exp9072 (now JodyPutra-dev)
# Licensed under the MIT License. See the LICENSE file in the project root for full license information.

"""
Translation and configuration module for PortLinker application.

This module contains all translation strings, default configuration values,
and language management functionality for the PortLinker application.
"""

# Default port configuration
DEFAULT_PORTS = [80, 443, 9072]

# Translation dictionary containing all UI strings in supported languages
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
        "tab_cloudflare": "Cloudflare Tunnel",
        "cf_tunnel_ip_label": "Target IP Address:",
        "cf_tunnel_port_label": "Target Port:",
        "cf_start_tunnel_btn": "Start Tunnel",
        "cf_stop_tunnel_btn": "Stop Tunnel",
        "cf_status_stopped": "Status: Tunnel Stopped",
        "cf_status_starting": "Status: Starting tunnel...",
        "cf_status_running": "Status: Tunnel Running",
        "cf_tunnel_url_label": "Tunnel URL:",
        "cf_copy_url_btn": "Copy URL",
        "cf_info_text": "Cloudflare Tunnel creates a secure connection to expose your local service to the internet. Enter the IP and port of your local service.",
        "cf_error_no_ip": "Please enter a valid IP address.",
        "cf_error_no_port": "Please enter a valid port number.",
        "cf_error_start_failed": "Failed to start tunnel. Make sure cloudflared is installed.",
        "cf_success_started": "Tunnel started successfully!",
        "cf_success_stopped": "Tunnel stopped successfully.",
        "cf_url_copied": "URL copied to clipboard!",
        "cf_detect_ip_btn": "Detect IP",
        "cf_wsl_warning": "Important: If your service is running in WSL, first enable port forwarding in the 'Port Forwarding' tab to forward the WSL IP to your Windows IP, then use your Windows IP here for the tunnel.",
        "cf_not_installed_notice": "Cloudflare Tunnel service is not installed on the system.",
        "cf_install_guide_link": "See installation guide in Troubleshooting tab.",
        "cf_install_guide_title": "Cloudflare Tunnel Installation Guide",
        "cf_install_guide_intro": "Follow these steps to install Cloudflare Tunnel (cloudflared) on your Windows system:",
        "cf_install_step1_title": "Download cloudflared",
        "cf_install_step1_desc": "Visit the official Cloudflare GitHub releases page and download the Windows version (cloudflared-windows-amd64.exe)",
        "cf_install_step1_link": "https://github.com/cloudflare/cloudflared/releases/latest",
        "cf_install_step2_title": "Rename and Place the File",
        "cf_install_step2_desc": "Rename the downloaded file to <code>cloudflared.exe</code> and place it in one of these locations:",
        "cf_install_step2_option1": "In the same folder as PortLinker.exe (easiest method)",
        "cf_install_step2_option2": "In a dedicated folder like <code>C:\\Program Files\\cloudflared\\</code>",
        "cf_install_step2_option3": "In your user folder: <code>%LOCALAPPDATA%\\cloudflared\\</code>",
        "cf_install_step3_title": "Add to Windows PATH (Optional but Recommended)",
        "cf_install_step3_desc": "To use cloudflared from anywhere, add it to your system PATH:",
        "cf_install_step3_substep1": "Right-click 'This PC' or 'My Computer' and select 'Properties'",
        "cf_install_step3_substep2": "Click 'Advanced system settings' → 'Environment Variables'",
        "cf_install_step3_substep3": "Under 'System variables', find and select 'Path', then click 'Edit'",
        "cf_install_step3_substep4": "Click 'New' and add the folder path where you placed cloudflared.exe",
        "cf_install_step3_substep5": "Click 'OK' on all dialogs to save",
        "cf_install_step4_title": "Restart PortLinker",
        "cf_install_step4_desc": "Close and reopen PortLinker. The Cloudflare Tunnel tab should now be enabled.",
        "cf_install_verify_title": "Verify Installation",
        "cf_install_verify_desc": "Open Command Prompt and type <code>cloudflared --version</code>. If installed correctly, you'll see the version number.",
        "cf_install_note": "Note: If you placed cloudflared.exe in the same folder as PortLinker, you don't need to add it to PATH.",
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
        "tab_cloudflare": "Cloudflare Tunnel",
        "cf_tunnel_ip_label": "Alamat IP Target:",
        "cf_tunnel_port_label": "Port Target:",
        "cf_start_tunnel_btn": "Mulai Tunnel",
        "cf_stop_tunnel_btn": "Hentikan Tunnel",
        "cf_status_stopped": "Status: Tunnel Dihentikan",
        "cf_status_starting": "Status: Memulai tunnel...",
        "cf_status_running": "Status: Tunnel Berjalan",
        "cf_tunnel_url_label": "URL Tunnel:",
        "cf_copy_url_btn": "Salin URL",
        "cf_info_text": "Cloudflare Tunnel membuat koneksi aman untuk mengekspos layanan lokal Anda ke internet. Masukkan IP dan port layanan lokal Anda.",
        "cf_error_no_ip": "Silakan masukkan alamat IP yang valid.",
        "cf_error_no_port": "Silakan masukkan nomor port yang valid.",
        "cf_error_start_failed": "Gagal memulai tunnel. Pastikan cloudflared sudah terinstal.",
        "cf_success_started": "Tunnel berhasil dimulai!",
        "cf_success_stopped": "Tunnel berhasil dihentikan.",
        "cf_url_copied": "URL berhasil disalin!",
        "cf_detect_ip_btn": "Deteksi IP",
        "cf_wsl_warning": "Penting: Jika layanan Anda berjalan di WSL, aktifkan port forwarding di tab 'Port Forwarding' terlebih dahulu untuk meneruskan IP WSL ke IP Windows Anda, lalu gunakan IP Windows Anda di sini untuk tunnel.",
        "cf_not_installed_notice": "Layanan Cloudflare Tunnel belum terinstal di sistem.",
        "cf_install_guide_link": "Lihat panduan instalasi di tab Pemecahan Masalah.",
        "cf_install_guide_title": "Panduan Instalasi Cloudflare Tunnel",
        "cf_install_guide_intro": "Ikuti langkah-langkah berikut untuk menginstal Cloudflare Tunnel (cloudflared) di sistem Windows Anda:",
        "cf_install_step1_title": "Unduh cloudflared",
        "cf_install_step1_desc": "Kunjungi halaman rilis GitHub resmi Cloudflare dan unduh versi Windows (cloudflared-windows-amd64.exe)",
        "cf_install_step1_link": "https://github.com/cloudflare/cloudflared/releases/latest",
        "cf_install_step2_title": "Ubah Nama dan Tempatkan File",
        "cf_install_step2_desc": "Ubah nama file yang diunduh menjadi <code>cloudflared.exe</code> dan tempatkan di salah satu lokasi berikut:",
        "cf_install_step2_option1": "Di folder yang sama dengan PortLinker.exe (metode termudah)",
        "cf_install_step2_option2": "Di folder khusus seperti <code>C:\\Program Files\\cloudflared\\</code>",
        "cf_install_step2_option3": "Di folder pengguna Anda: <code>%LOCALAPPDATA%\\cloudflared\\</code>",
        "cf_install_step3_title": "Tambahkan ke Windows PATH (Opsional tapi Disarankan)",
        "cf_install_step3_desc": "Untuk menggunakan cloudflared dari mana saja, tambahkan ke PATH sistem Anda:",
        "cf_install_step3_substep1": "Klik kanan 'This PC' atau 'My Computer' dan pilih 'Properties'",
        "cf_install_step3_substep2": "Klik 'Advanced system settings' → 'Environment Variables'",
        "cf_install_step3_substep3": "Di bawah 'System variables', cari dan pilih 'Path', lalu klik 'Edit'",
        "cf_install_step3_substep4": "Klik 'New' dan tambahkan path folder tempat Anda meletakkan cloudflared.exe",
        "cf_install_step3_substep5": "Klik 'OK' pada semua dialog untuk menyimpan",
        "cf_install_step4_title": "Restart PortLinker",
        "cf_install_step4_desc": "Tutup dan buka kembali PortLinker. Tab Cloudflare Tunnel sekarang harus diaktifkan.",
        "cf_install_verify_title": "Verifikasi Instalasi",
        "cf_install_verify_desc": "Buka Command Prompt dan ketik <code>cloudflared --version</code>. Jika terinstal dengan benar, Anda akan melihat nomor versi.",
        "cf_install_note": "Catatan: Jika Anda meletakkan cloudflared.exe di folder yang sama dengan PortLinker, Anda tidak perlu menambahkannya ke PATH.",
    }
}

# Module-level private variable for current language state (default to Indonesian)
_current_language = "id"


def get_text(key: str, **kwargs) -> str:
    """
    Get translated text for the given key in the current language.
    
    Args:
        key: Translation key to look up in the TRANSLATIONS dictionary
        **kwargs: Optional keyword arguments for string formatting
    
    Returns:
        Translated text string, with optional formatting applied.
        If key is not found, returns the key itself.
    
    Example:
        >>> get_text("window_title")
        'PortLinker'
        >>> get_text("status_enabled", listen_ip="192.168.1.1", target_ip="172.0.0.1", ports="80,443")
        'Status: Port Forwarding Enabled\\nForwarding 192.168.1.1:80,443 → 172.0.0.1:80,443'
    """
    text = TRANSLATIONS[_current_language].get(key, key)
    if kwargs:
        return text.format(**kwargs)
    return text


def get_current_language() -> str:
    """
    Get the current application language code.
    
    Returns:
        Current language code ("en" for English or "id" for Indonesian)
    
    Example:
        >>> get_current_language()
        'id'
    """
    return _current_language


def set_current_language(lang: str) -> None:
    """
    Set the current application language.
    
    Args:
        lang: Language code to set ("en" for English or "id" for Indonesian)
    
    Raises:
        ValueError: If the provided language code is not supported
    
    Example:
        >>> set_current_language("en")
        >>> get_current_language()
        'en'
    """
    global _current_language
    if lang not in TRANSLATIONS:
        raise ValueError(f"Unsupported language: {lang}. Supported languages: {list(TRANSLATIONS.keys())}")
    _current_language = lang


def toggle_language() -> str:
    """
    Toggle between English and Indonesian languages.
    
    Returns:
        The new current language code after toggling
    
    Example:
        >>> set_current_language("id")
        >>> toggle_language()
        'en'
        >>> toggle_language()
        'id'
    """
    global _current_language
    _current_language = "en" if _current_language == "id" else "id"
    return _current_language
