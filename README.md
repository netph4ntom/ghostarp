# GhostARP v1.5 - Interactive ARP Spoofing & MITM Framework

GhostARP adalah tool pembungkus (wrapper) interaktif untuk ARP Spoofing, Man-in-the-Middle (MITM), dan Denial of Service (DoS) yang dirancang untuk pengujian keamanan jaringan. Tool ini kini dilengkapi dengan antarmuka **Interactive Dashboard** modern berbasis terminal menggunakan library `rich`.

---

## Fitur Utama

- **Direct Dashboard Boot**: Melewatkan input wizard CLI yang lambat. Program langsung masuk ke dashboard setup saat dijalankan.
- **Setup & Attack Mode**: Dua antarmuka dinamis untuk fase konfigurasi (`SETUP`) dan fase penyerangan (`ATTACK ACTIVE`).
- **Asynchronous Background Scanning**: Melakukan ARP sweep dan resolusi MAC gateway secara otomatis di background tanpa membekukan layar terminal.
- **Easy Targeting (Index Selection)**: Menampilkan host aktif di jaringan dengan nomor indeks (misal `[1]`, `[2]`). Anda cukup mengetik `add 1` untuk menjadikannya target.
- **Multi-target & Dynamic Control**: Tambah/hapus target, ubah mode, atau pause/resume serangan langsung di tengah proses penyerangan tanpa me-restart program.
- **Dua Mode Utama**:
  - **MITM**: Meneruskan paket internet korban sambil melakukan sniffing data HTTP (termasuk deteksi kredensial) & DNS.
  - **KILL**: Memutus total koneksi internet korban (ARP poisoning tanpa IP forwarding).
- **Auto ARP Restoration**: Mengembalikan cache ARP semua target & gateway secara otomatis saat keluar (`Ctrl+C` / `quit`) atau ketika target dihapus.
- **Cross-Platform Compatibility**: Handler terminal raw-mode dan input perintah didesain agar dapat dijalankan dan diuji di Windows maupun Linux.

---

## Kebutuhan & Instalasi

Pastikan Anda memiliki hak akses root/administrator saat menjalankan serangan paket.

### 1. Install Dependensi
Gunakan berkas `requirements.txt` untuk menginstal dependensi:
```bash
pip install -r requirements.txt
```
*Catatan: Dependensi utama adalah `scapy` dan `rich`.*

### 2. Jalankan Program
```bash
sudo python3 main.py
```
---

## Panduan Perintah Interaktif

Ketik perintah-perintah berikut di baris perintah bawah layar dashboard:

### A. Perintah pada Setup Mode (`Setup Config >`)
| Perintah | Deskripsi |
| --- | --- |
| `set iface <nama>` | Mengganti network interface aktif (misal `eth0` / `wlan0`). |
| `set gw <ip>` | Mengganti IP default gateway. |
| `set mode <mitm\|kill>` | Menentukan mode serangan (MITM atau KILL). |
| `macspoof <on\|off>` | Mengaktifkan/menonaktifkan pengacakan MAC address interface. |
| `dns add <domain>=<ip>` | Menambahkan peta spoofing DNS. |
| `dns del <domain>` | Menghapus domain dari spoofing DNS. |
| `dns list` | Menampilkan seluruh daftar DNS spoofing yang aktif. |
| `add <ip\|nomor>` | Menambahkan target berdasarkan IP address atau nomor indeks host aktif. |
| `del <ip\|nomor\|all>`| Menghapus target tertentu atau seluruh target. |
| `scan` | Memulai ulang pemindaian host aktif di jaringan (ARP sweep). |
| `start` / `run` | Memulai serangan ARP spoofing (pindah ke mode Attack). |
| `quit` / `exit` | Keluar dari aplikasi. |

### B. Perintah pada Attack Mode (`Attack Active >`)
| Perintah | Deskripsi |
| --- | --- |
| `stop` | Menghentikan serangan, memulihkan tabel ARP korban, dan kembali ke Setup Mode. |
| `pause` | Menjeda pengiriman paket poison ARP (korban tetap di daftar target). |
| `resume` | Melanjutkan kembali pengiriman paket poison ARP. |
| `mode <mitm\|kill>` | Mengubah mode serangan di tengah jalan (runtime). |
| `add <ip>` | Menambahkan korban baru secara dinamis saat serangan berjalan. |
| `del <ip>` | Menghapus korban secara dinamis (ARP korban tersebut langsung dipulihkan). |
| `dns add <d=ip>` | Menambahkan entri DNS spoofing baru saat serangan berjalan. |
| `quit` / `exit` | Menghentikan serangan, memulihkan tabel ARP, dan menutup aplikasi secara bersih. |

---

## Penafian (Disclaimer)
Tool ini dibuat khusus untuk keperluan edukasi, pengujian penetrasi resmi, dan audit keamanan jaringan yang dimiliki secara pribadi atau telah mendapatkan izin tertulis. Penyalahgunaan terhadap jaringan tanpa izin adalah ilegal dan melanggar hukum. Pengembang tidak bertanggung jawab atas segala kerusakan atau tuntutan hukum yang disebabkan oleh penggunaan tool ini.
