from ftplib import FTP

ip_router = "192.168.1.1"
username = "admin"
password = "adminadmin"

try:
    ftp = FTP()
    ftp.connect(ip_router, 21, timeout=10)
    ftp.login(username, password)
    print("[+] Login berhasil!")

    ftp.set_pasv(True)

    # Lihat working directory sekarang
    current_dir = ftp.pwd()
    print(f"[+] Current Directory: {current_dir}")

    # List file/folder
    print("\n[+] Daftar file/folder:")
    files = ftp.nlst()
    if files:
        for f in files:
            print(f)
    else:
        print("[!] Tidak ada file/folder ditemukan di direktori ini.")

    # Coba manual masuk ke beberapa direktori umum (optional)
    common_dirs = ['config', 'cfg', 'admin', 'system', 'data', 'backup']
    for d in common_dirs:
        try:
            print(f"\n[+] Mencoba masuk ke folder: {d}")
            ftp.cwd(d)
            files = ftp.nlst()
            print(f"Isi folder {d}: {files}")
            ftp.cwd('..')  # Balik ke atas
        except Exception as e:
            print(f"[-] Gagal masuk folder {d}: {e}")

    ftp.quit()
    print("\n[+] Koneksi ditutup.")
except Exception as e:
    print(f"[-] Error: {e}")
