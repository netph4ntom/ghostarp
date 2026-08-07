# GhostARP

## Deskripsi
GhostARP adalah tool (wrapper) untuk ARP Spoofing, Man-in-the-Middle (MITM), dan Denial of Service (DoS) yang dirancang untuk pengujian keamanan jaringan. Tool ini hadir dengan **Interactive Dashboard** berbasis terminal yang memudahkan kontrol serangan secara dinamis, serta mendukung eksekusi otomatis melalui antarmuka Command-Line (CLI).

## Fitur
- **Dua Mode Utama**:
  - **MITM**: Meneruskan lalu lintas korban (IP Forwarding) sambil menyadap (sniffing) request HTTP (termasuk kredensial), TLS SNI (domain HTTPS), dan query DNS.
  - **KILL**: Memutus total koneksi internet korban menggunakan ARP poison.
- **Interactive Dashboard**: Antarmuka terminal interaktif dengan library `rich` untuk melihat status, log, daftar host aktif, kredensial yang didapat, dan query DNS secara real-time.
- **Dynamic Control**: Tambah/hapus target, jeda/lanjutkan serangan, ubah peta spoofing DNS, atau ganti mode serangan (`mitm`/`kill`) saat serangan sedang berlangsung.
- **Auto-Discovery & Validation**: Pemindaian ARP jaringan (ARP sweep) dan resolusi MAC gateway yang berjalan asinkron di latar belakang.
- **DNS Spoofing**: Memanipulasi respons DNS untuk mengalihkan domain tertentu ke IP yang diinginkan.
- **Auto ARP Restoration**: Memulihkan cache ARP korban dan gateway secara otomatis dan bersih setelah serangan dihentikan untuk mencegah kerusakan jaringan yang persisten.
- **MAC Spoofing**: Fitur pengacakan alamat MAC untuk menyembunyikan identitas antarmuka jaringan penyerang.

## Instalasi
Pastikan sistem Anda sudah menginstal Python 3. Tool ini merekomendasikan sistem operasi Linux karena membutuhkan kapabilitas manipulasi paket tingkat rendah.

1. Install dependensi :
   ```bash
   sudo apt update
   sudo apt install python3-scapy python3-rich
   ```

2. Atau melalui `pip` menggunakan file `requirements.txt`:
   ```bash
   pip install -r requirements.txt
   ```

## Penggunaan
Tool ini harus dijalankan dengan hak akses root/administrator agar dapat memanipulasi lalu lintas jaringan.

### Masuk ke Dashboard Interaktif
```bash
sudo python3 main.py
```

Setelah masuk ke dalam dashboard, Anda dapat menggunakan perintah-perintah interaktif berikut untuk mengatur dan mengontrol serangan:

#### Perintah Setup & Konfigurasi (Setup Mode)
- `help` : Menampilkan menu bantuan.
- `scan` : Memindai (ARP sweep) jaringan untuk mencari host/target yang aktif.
- `add <ip>` atau `add <nomor>` : Menambahkan target berdasarkan IP atau nomor urut dari hasil scan. (Dapat menggunakan koma untuk multi-target, misal: `add 1,2,3` atau `add 192.168.1.10,192.168.1.11`).
- `del <ip>` atau `del <nomor>` atau `del all` : Menghapus target dari daftar.
- `set iface <nama_interface>` : Mengubah interface jaringan yang digunakan (misal: `set iface wlan0`).
- `set gw <ip>` : Mengatur IP Gateway secara manual.
- `set mode <mitm|kill>` : Mengubah mode serangan. `mitm` untuk sniffing (internet tetap jalan), `kill` untuk memutus koneksi internet korban.
- `macspoof <on|off>` : Mengaktifkan atau menonaktifkan fitur MAC Spoofing (MAC akan diacak saat serangan dimulai).
- `dns add <domain>=<ip>` : Menambahkan aturan DNS Spoofing (misal: `dns add facebook.com=192.168.1.100`).
- `dns del <domain>` : Menghapus aturan DNS Spoofing.
- `dns list` : Melihat daftar aturan DNS Spoofing yang aktif.
- `start` : Memulai serangan berdasarkan konfigurasi dan target yang telah diatur.
- `quit` atau `exit` : Keluar dari program.

#### Perintah Kontrol (Saat Serangan Berlangsung / Attack Mode)
Anda dapat mengubah parameter serangan secara dinamis (On-the-Fly) tanpa harus menghentikan tool:
- `help` : Menampilkan menu bantuan saat serangan berlangsung.
- `stop` : Menghentikan serangan, memulihkan ARP korban (restore), dan kembali ke Setup Mode.
- `pause` : Menjeda pengiriman paket ARP poison (serangan dihentikan sementara tanpa menghapus target).
- `resume` : Melanjutkan pengiriman paket ARP poison yang sedang dijeda.
- `mode <mitm|kill>` : Mengubah mode serangan secara langsung saat berjalan.
- `add <ip|nomor>` / `del <ip|nomor|all>` : Menambah atau menghapus target secara dinamis saat serangan berjalan. ARP cache target yang dihapus akan dipulihkan secara otomatis.
- `dns add <domain>=<ip>` / `dns del <domain>` : Mengubah aturan DNS spoofing saat serangan berjalan.
- `scan` : Melakukan pemindaian jaringan di latar belakang.
- `quit` atau `exit` : Menghentikan serangan, memulihkan ARP secara otomatis, dan keluar dari program.

### Eksekusi Cepat via Argumen CLI
Anda juga dapat langsung melewati tahap setup dan melancarkan serangan menggunakan argumen dari terminal:

```bash
# Menyerang target tertentu dengan mode KILL (memutus koneksi internet korban)
sudo python3 main.py -t 192.168.1.5 --mode kill

# Menyerang beberapa target sekaligus dari file dengan mode MITM (sniffing) dan DNS spoofing
sudo python3 main.py --targets-file victims.txt --mode mitm --dns-file dns.txt

# Menyerang target spesifik dengan MAC Spoofing aktif pada antarmuka wlan0
sudo python3 main.py -i wlan0 -t 192.168.1.10 --mac-spoof
```

Untuk melihat menu bantuan lengkap:
```bash
python3 main.py --help
```

## Peringatan (Disclaimer)
Tool ini dikembangkan **khusus untuk keperluan edukasi, riset, dan audit keamanan jaringan (penetration testing)** di jaringan milik Anda sendiri atau jaringan di mana Anda telah memiliki izin pengujian secara eksplisit.

Segala bentuk penyalahgunaan tool ini untuk melakukan serangan pada jaringan pihak ketiga tanpa izin merupakan tindakan ilegal. Pengembang tidak bertanggung jawab atas segala kerusakan, gangguan layanan jaringan, pencurian data, atau tuntutan hukum yang timbul dari penyalahgunaan perangkat lunak ini. Gunakan dengan bijak dan bertanggung jawab.
