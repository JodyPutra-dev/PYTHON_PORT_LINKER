import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
import subprocess
import sys
import ctypes
import os
import time
import socket
import traceback

# Daftar port default
DEFAULT_PORTS = [80, 443, 9072]

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
                options = ["Matikan Proses Python", "Lanjutkan", "Batal"]
                result = messagebox.askyesnocancel(
                    "Python Menggunakan Port",
                    f"Port {ports_str} digunakan oleh Python (kemungkinan aplikasi ini atau skrip Python lain).\n\n" +
                    "Apa yang ingin Anda lakukan?\n\n" +
                    "- Yes: Matikan proses Python yang menggunakan port\n" +
                    "- No: Coba atur port forwarding tetap\n" +
                    "- Cancle: Batalkan operasi",
                    icon=messagebox.QUESTION
                )
                
                if result is None:  # Batal
                    return False
                elif result:  # Ya - Matikan proses
                    for port, pid, _ in python_processes:
                        if kill_process_by_pid(pid):
                            messagebox.showinfo("Berhasil", f"Berhasil mematikan proses yang menggunakan port {port}")
                        else:
                            messagebox.showwarning("Peringatan", f"Gagal mematikan proses yang menggunakan port {port}")
                    # Tunggu sebentar agar proses berakhir
                    time.sleep(1)
                # else: Tidak - Lanjutkan
            else:
                # Proses non-Python biasa
                result = messagebox.askyesno(
                    "Konflik Port", 
                    f"Port berikut sudah digunakan oleh aplikasi lain:\n{ports_str}\n\n" +
                    "Apakah Anda ingin melanjutkan?\n\n" +
                    "Klik Yes untuk mencoba mengatur port forwarding tetap.\n" +
                    "Klik No untuk membatalkan."
                )
                if not result:
                    return False
        return True
        
    # Jika kita sampai di sini, XAMPP sedang berjalan dan perlu dihentikan
    ports_list = ", ".join([str(p) for p in ports_in_use])
    result = messagebox.askyesno(
        "XAMPP Berjalan", 
        f"XAMPP sepertinya sedang berjalan dan menggunakan port {ports_list}. " +
        "Apakah Anda ingin menghentikan XAMPP untuk melanjutkan?\n\n" +
        "Klik Yes untuk menghentikan XAMPP dan melanjutkan.\n" +
        "Klik No untuk membatalkan."
    )
    
    if not result:
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
        messagebox.showwarning(
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
        # Ambil dari entri teks port
        port_text = ports_entry.get().strip()
        
        # Jika kosong, gunakan port default
        if not port_text:
            return DEFAULT_PORTS
            
        # Jika "all", gunakan port default
        if port_text.lower() == "all":
            return DEFAULT_PORTS
            
        # Proses string port
        port_list = []
        for part in port_text.split(','):
            part = part.strip()
            
            # Cek apakah ini adalah rentang port (misal: 8000-8005)
            if '-' in part:
                start, end = part.split('-')
                try:
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    # Tambahkan semua port dalam rentang
                    port_list.extend(range(start_port, end_port + 1))
                except ValueError:
                    messagebox.showwarning("Format Port", f"Format rentang port tidak valid: {part}")
            else:
                # Port tunggal
                try:
                    port_list.append(int(part))
                except ValueError:
                    messagebox.showwarning("Format Port", f"Port harus berupa angka: {part}")
                    
        # Hapus duplikat
        port_list = list(set(port_list))
        
        # Validasi
        if not port_list:
            return DEFAULT_PORTS
            
        return port_list
    except:
        return DEFAULT_PORTS

def add_port():
    """Tambahkan port baru ke daftar."""
    try:
        new_port = simpledialog.askinteger("Tambah Port", "Masukkan nomor port:")
        if new_port is not None and new_port > 0:
            current_ports = ports_entry.get().strip()
            if current_ports:
                if current_ports.lower() == "all":
                    # Mulai dari port default + port baru
                    new_ports = ','.join(map(str, DEFAULT_PORTS + [new_port]))
                else:
                    new_ports = current_ports + f", {new_port}"
            else:
                new_ports = str(new_port)
                
            ports_entry.delete(0, tk.END)
            ports_entry.insert(0, new_ports)
    except:
        pass

def reset_ports():
    """Reset daftar port ke default."""
    try:
        ports_entry.delete(0, tk.END)
        ports_entry.insert(0, "all")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal mereset port: {str(e)}")

def enable_port_forwarding():
    ip = ip_entry.get().strip()
    listen_ip = listen_ip_entry.get().strip() or "0.0.0.0"
    
    if not ip:
        messagebox.showerror("Error", "Silakan masukkan alamat IP target yang valid.")
        return
    
    # Dapatkan daftar port aktif
    active_ports = get_active_ports()
    if not active_ports:
        messagebox.showerror("Error", "Tidak ada port yang dipilih untuk forwarding.")
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
            messagebox.showinfo("Firewall Diatur", f"Aturan firewall berhasil ditambahkan untuk port: {port_list}")
        
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
        status_label.config(text=status_text, fg="green")
        
        # Tampilkan aturan saat ini
        show_current_rules()
        
        # Tampilkan info jaringan dalam dialog terpisah
        messagebox.showinfo(
            "Info Koneksi", 
            f"Port forwarding diaktifkan:\n{listen_ip}:{port_list_str} → {ip}:{port_list_str}\n\n" +
            f"{network_info}\n\n" +
            "Jika Anda tidak dapat terhubung dari ponsel, periksa:\n" +
            "1. Ponsel dan PC berada di jaringan yang sama\n" +
            "2. Coba gunakan IP yang tercantum di atas\n" +
            "3. Windows Firewall mungkin memblokir koneksi"
        )
        
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Gagal mengaktifkan port forwarding:\n{e.output.decode()}")

def disable_port_forwarding():
    try:
        # Dapatkan port-port aktif
        active_ports = get_active_ports()
        
        # Dapatkan IP listen tertentu
        listen_ip = listen_ip_entry.get().strip() or "0.0.0.0"
        
        # Reset semua aturan (ini menghapus SEMUA port forwarding)
        if active_ports:
            result = messagebox.askyesnocancel(
                "Nonaktifkan Port Forwarding",
                "Anda dapat menonaktifkan hanya port yang dipilih atau semua port forwarding yang ada.\n\n" +
                "- Klik Yes untuk menghapus HANYA port yang dipilih\n" +
                "- Klik No untuk menghapus SEMUA port forwarding\n" +
                "- Klik Cancel untuk membatalkan operasi"
            )
            
            if result is None:  # User clicked Cancel
                return
            
            if result:
                # Hapus hanya port yang dipilih
                for port in active_ports:
                    # Hapus aturan dengan listen_ip tertentu
                    if listen_ip != "0.0.0.0":
                        try:
                            subprocess.run([
                                "netsh", "interface", "portproxy", "delete", 
                                "v4tov4", f"listenport={port}", f"listenaddress={listen_ip}"
                            ], check=False, capture_output=True)
                        except:
                            pass
                    
                    # Hapus aturan untuk semua antarmuka
                    try:
                        subprocess.run([
                            "netsh", "interface", "portproxy", "delete", 
                            "v4tov4", f"listenport={port}", "listenaddress=0.0.0.0"
                        ], check=False, capture_output=True)
                    except:
                        pass
            else:
                # Hapus SEMUA port forwarding dengan reset
                try:
                    subprocess.run([
                        "netsh", "interface", "portproxy", "reset"
                    ], check=False, capture_output=True)
                except:
                    pass
        else:
            # Tidak ada port yang dipilih, hapus semua
            result = messagebox.askyesnocancel(
                "Nonaktifkan Port Forwarding",
                "Anda akan menghapus SEMUA port forwarding yang ada.\n\n" +
                "- Klik Yes untuk melanjutkan\n" +
                "- Klik Cancel untuk membatalkan operasi"
            )
            
            if result is None:  # User clicked Cancel
                return
                
            if result:  # User clicked Yes
                try:
                    subprocess.run([
                        "netsh", "interface", "portproxy", "reset"
                    ], check=False, capture_output=True)
                except:
                    pass
        
        status_label.config(text="Status: Port Forwarding Dinonaktifkan", fg="blue")
        
        # Bersihkan dan perbarui tampilan aturan
        show_current_rules()
        
        messagebox.showinfo("Berhasil", "Port forwarding telah dinonaktifkan")
    except Exception as e:
        messagebox.showerror("Error", f"Gagal menonaktifkan port forwarding: {str(e)}")

def show_current_rules():
    try:
        # Dapatkan aturan portproxy saat ini
        result = subprocess.check_output(["netsh", "interface", "portproxy", "show", "all"], 
                                        stderr=subprocess.STDOUT, 
                                        universal_newlines=True)
        
        # Perbarui widget teks dengan aturan
        rules_text.delete(1.0, tk.END)
        rules_text.insert(tk.END, result)
    except subprocess.CalledProcessError as e:
        rules_text.delete(1.0, tk.END)
        rules_text.insert(tk.END, f"Error mengambil aturan: {str(e)}")

def create_help_tab(notebook):
    """Buat tab bantuan dengan informasi pemecahan masalah."""
    help_frame = ttk.Frame(notebook, padding=10)
    
    # Buat area teks yang dapat di-scroll
    help_text = tk.Text(help_frame, wrap=tk.WORD, width=60, height=20)
    scrollbar = tk.Scrollbar(help_frame, command=help_text.yview)
    help_text.config(yscrollcommand=scrollbar.set)
    
    help_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    # Tambahkan informasi pemecahan masalah
    help_content = """Pemecahan Masalah Koneksi Ponsel:

1. Pastikan Kedua Perangkat Berada di Jaringan yang Sama
   - Ponsel dan PC Anda harus terhubung ke jaringan WiFi yang sama
   - Jaringan rumah mungkin mengisolasi perangkat untuk keamanan (periksa pengaturan router)

2. Periksa Windows Firewall
   - Windows Firewall mungkin memblokir koneksi masuk
   - Nonaktifkan Windows Firewall sementara atau tambahkan aturan untuk port yang digunakan

3. Coba Alamat IP yang Berbeda
   - Gunakan alamat IP yang ditampilkan di dialog Info Koneksi
   - PC Anda mungkin memiliki beberapa alamat IP - coba masing-masing dari ponsel Anda

4. Uji Akses Lokal Terlebih Dahulu
   - Sebelum mencoba dari ponsel, verifikasi http://localhost berfungsi di PC Anda
   - Kemudian coba gunakan alamat IP tertentu di browser PC

5. Pengaturan Router
   - Beberapa router memblokir permintaan jaringan internal secara default
   - Periksa apakah router Anda memiliki isolasi AP atau isolasi klien yang diaktifkan

6. Gunakan Protokol dan Port yang Benar
   - Gunakan http:// (bukan https://) saat terhubung ke port 80
   - Sertakan port di URL jika menggunakan port non-standar
     Contoh: http://192.168.0.2:9072

7. Informasi Format Port:
   - Masukkan "all" untuk menggunakan semua port default (80, 443, 9072)
   - Masukkan nomor port tunggal, mis: 8080
   - Masukkan beberapa port dipisahkan koma, mis: 80, 443, 8080
   - Masukkan rentang port, mis: 8000-8010
   - Kombinasi dari format di atas: 80, 443, 8000-8010, 9072
    """
    
    help_text.insert(tk.END, help_content)
    help_text.config(state=tk.DISABLED)  # Jadikan hanya-baca
    
    # Tambahkan tombol untuk memeriksa jaringan
    check_btn = tk.Button(help_frame, text="Periksa Konfigurasi Jaringan", 
                         command=lambda: show_network_info())
    check_btn.pack(side=tk.BOTTOM, pady=10)
    
    return help_frame

def show_network_info():
    """Tampilkan konfigurasi jaringan terperinci dalam popup."""
    hostname, ip_addresses, ipconfig = get_network_info()
    
    # Buat jendela baru
    info_window = tk.Toplevel()
    info_window.title("Informasi Jaringan")
    info_window.geometry("600x400")
    
    # Tambahkan area teks dengan scrollbar
    text_frame = tk.Frame(info_window)
    text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    text_widget = tk.Text(text_frame, wrap=tk.WORD)
    scrollbar = tk.Scrollbar(text_frame, command=text_widget.yview)
    text_widget.config(yscrollcommand=scrollbar.set)
    
    text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    # Masukkan info jaringan
    if hostname:
        text_widget.insert(tk.END, f"Nama Host: {hostname}\n\n")
    
    if ip_addresses and len(ip_addresses) > 1:
        text_widget.insert(tk.END, "Alamat IP:\n")
        for ip in ip_addresses[2]:
            text_widget.insert(tk.END, f"- {ip}\n")
        text_widget.insert(tk.END, "\n")
    
    # Tambahkan info firewall
    firewall_active, rules = check_firewall_status()
    text_widget.insert(tk.END, f"Firewall Aktif: {firewall_active}\n\n")
    
    if rules:
        text_widget.insert(tk.END, "Aturan Firewall untuk Port Forward:\n")
        text_widget.insert(tk.END, rules if rules else "Tidak ditemukan aturan khusus\n")
        text_widget.insert(tk.END, "\n")
    
    # Tambahkan output ipconfig
    if ipconfig:
        text_widget.insert(tk.END, "Antarmuka Jaringan:\n")
        text_widget.insert(tk.END, ipconfig)
    
    # Tampilkan status port yang aktif
    active_ports = get_active_ports()
    text_widget.insert(tk.END, "\nStatus Port Aktif:\n")
    for port in active_ports:
        status = "Digunakan" if check_port_in_use(port) else "Bebas"
        text_widget.insert(tk.END, f"Port {port}: {status}\n")
    
    # Jadikan teks hanya-baca
    text_widget.config(state=tk.DISABLED)

# Program utama dengan penanganan error
if __name__ == "__main__":
    try:
        # Build UI
        root = tk.Tk()
        root.title("Pengatur Port Forwarding")
        
        # Dapatkan alamat IP lokal di awal
        local_ip = get_local_ip()
        
        # Pastikan program tidak langsung tertutup jika terjadi error
        def show_error_and_exit(error_type, error_value, error_traceback):
            error_msg = "".join(traceback.format_exception(error_type, error_value, error_traceback))
            messagebox.showerror("Error Fatal", f"Terjadi error:\n\n{error_msg}")
            if root:
                root.destroy()
        
        # Atur penanganan error global
        sys.excepthook = show_error_and_exit
        
        # Buat notebook (tab)
        notebook = ttk.Notebook(root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Tab utama
        main_frame = ttk.Frame(notebook, padding=10)
        notebook.add(main_frame, text="Port Forwarding")

        # Tab bantuan
        help_tab = create_help_tab(notebook)
        notebook.add(help_tab, text="Pemecahan Masalah")

        # Label dan entry untuk alamat IP Listen (IP Windows)
        listen_ip_label = tk.Label(main_frame, text="Alamat IP Listen (IP PC Anda):")
        listen_ip_label.grid(row=0, column=0, pady=(0, 10), sticky="e")

        listen_ip_entry = tk.Entry(main_frame, width=20)
        listen_ip_entry.grid(row=0, column=1, pady=(0, 10), sticky="w")
        listen_ip_entry.insert(0, local_ip)  # Gunakan IP lokal yang terdeteksi

        # Tombol untuk mereset IP ke otomatis
        reset_ip_btn = tk.Button(main_frame, text="Deteksi IP", 
                               command=lambda: (listen_ip_entry.delete(0, tk.END), 
                                              listen_ip_entry.insert(0, get_local_ip())))
        reset_ip_btn.grid(row=0, column=2, pady=(0, 10), padx=5, sticky="w")

        # Label dan entry untuk alamat IP Target (IP WSL)
        target_ip_label = tk.Label(main_frame, text="Alamat IP Target (IP WSL atau IP Tujuan):")
        target_ip_label.grid(row=1, column=0, pady=(0, 10), sticky="e")

        ip_entry = tk.Entry(main_frame, width=20)
        ip_entry.grid(row=1, column=1, pady=(0, 10), sticky="w")
        ip_entry.insert(0, "172.29.156.41")  # IP WSL default

        # Label dan entry untuk Port
        ports_label = tk.Label(main_frame, text="Port (all artinya 80, 443, 9072):")
        ports_label.grid(row=2, column=0, pady=(0, 10), sticky="e")

        # Frame untuk port entry dan tombol
        port_frame = tk.Frame(main_frame)
        port_frame.grid(row=2, column=1, pady=(0, 10), sticky="w")

        ports_entry = tk.Entry(port_frame, width=20)
        ports_entry.pack(side=tk.LEFT)
        ports_entry.insert(0, "all")  # Default: semua port (80, 443, 9072)

        # Tombol untuk menambahkan port baru
        add_port_btn = tk.Button(port_frame, text="+", command=add_port, width=2)
        add_port_btn.pack(side=tk.LEFT, padx=2)

        # Tombol untuk mereset port ke default
        reset_port_btn = tk.Button(port_frame, text="Reset", command=reset_ports, width=5)
        reset_port_btn.pack(side=tk.LEFT, padx=2)

        # Tombol untuk mengaktifkan/menonaktifkan port forwarding
        enable_btn = tk.Button(main_frame, text="Aktifkan Port Forwarding", command=enable_port_forwarding)
        enable_btn.grid(row=3, column=0, columnspan=3, pady=5, sticky="ew")

        disable_btn = tk.Button(main_frame, text="Nonaktifkan Port Forwarding", command=disable_port_forwarding)
        disable_btn.grid(row=4, column=0, columnspan=3, pady=5, sticky="ew")

        refresh_btn = tk.Button(main_frame, text="Refresh Aturan", command=show_current_rules)
        refresh_btn.grid(row=5, column=0, columnspan=3, pady=5, sticky="ew")

        # Tampilan status
        status_label = tk.Label(main_frame, text="Status: Tidak Diketahui", fg="black")
        status_label.grid(row=6, column=0, columnspan=3, pady=(10, 0))

        # Tampilan aturan
        rules_label = tk.Label(main_frame, text="Aturan Port Proxy Saat Ini:")
        rules_label.grid(row=7, column=0, columnspan=3, pady=(10, 0), sticky="w")

        rules_frame = tk.Frame(main_frame)
        rules_frame.grid(row=8, column=0, columnspan=3, pady=(5, 0), sticky="nsew")

        rules_text = tk.Text(rules_frame, height=10, width=60)
        rules_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(rules_frame, command=rules_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        rules_text.config(yscrollcommand=scrollbar.set)

        # Inisialisasi dengan aturan saat ini
        show_current_rules()
        
        # Mulai main loop
        root.mainloop()
        
    except Exception as e:
        # Tangkap semua error agar program tidak langsung tertutup
        error_msg = traceback.format_exc()
        messagebox.showerror("Error Fatal", f"Terjadi error tak terduga:\n\n{error_msg}")
        sys.exit(1)
