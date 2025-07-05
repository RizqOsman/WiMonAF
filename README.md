# WiMonAF - Wireless Monitor & Auth Flood
**by Rizq Osman**

WiMonAF is a Python-based tool designed to monitor clients and perform *Authentication Flood* attacks on Wi-Fi Access Points (APs). It is ideal for wireless network penetration testing and analyzing the security strength of APs.

---

## ✨ Features
- 🔍 Automatic SSID & BSSID scanning of nearby networks
- 📡 Real-time monitoring of clients attempting to connect to the target AP
- 💣 Authentication Flood attack using `mdk4`
- 💥 Deauthentication Attack (optional if PMF is disabled)
- 📈 Real-time statistics for packet count and detected clients
- 🔁 Auto-restart `mdk4` if it stops unexpectedly
- 📝 Automatic activity logging to a log file
- ⚙️ CLI argument support for flexible usage

---

## ⚙️ Installation

### 1. Install System Dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-pip aircrack-ng mdk4 net-tools
```
## 2. Install Python Modules
```bash
pip3 install scapy
```
## 3. Enable Monitor Mode 

Use your Wi-Fi interface (e.g., wlan0) and switch it to monitor mode: 
```bash
sudo airmon-ng start <yourinterface>
```
## 🚀 How to Run 
Automatic SSID & BSSID Scan (Interactive Mode) 
```bash
sudo python3 wimonaf.py -i wlan0mon
```
Manual Target Specification (Without Scanning)
```
sudo python3 wimonaf.py -i wlan0mon -b 94:83:C4:50:38:0C -s "TargetSSID"
```
Deauthentication Mode (Optional if PMF is Disabled)
```bash
sudo python3 wimonaf.py -i wlan0mon -b XX:XX:XX:XX:XX:XX -s "TargetSSID" --deauth
```
Display Version
```bash
sudo python3 wimonaf.py --version
```
## 📁 Output 

    All activities are automatically logged to a file:
```bash
authlog_YYYYMMDD_HHMMSS.txt
```

## ⚠️ Important Notes 

    This tool is intended for personal network security testing only .
    Do not use it on networks without permission, as it may violate laws in many countries.
    Ensure your Wi-Fi adapter supports monitor mode  and packet injection .
     

 
📊 Example Output 
```bash
[*] Monitoring clients attempting to connect to the target SSID...
[Client] 78:E3:5D:D4:9B:E4 is trying to connect to SSID 'Workshop 08'
[+] Total clients detected: 4

[*] mdk4 is running | Total packets sent: 8000
[!] mdk4 has stopped, retrying in 3 seconds...
```
