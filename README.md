
# WiMonAF - Wireless Monitor & Auth Flood
**by Rizq Osman**

WiMonAF adalah tool berbasis Python untuk melakukan pemantauan client dan serangan *Authentication Flood* terhadap Access Point (AP) Wi-Fi. Cocok digunakan untuk pengujian penetrasi jaringan nirkabel dan analisis kekuatan keamanan AP.

---

## ✨ Fitur
- 🔍 Auto-scan SSID & BSSID dari jaringan terdekat
- 📡 Monitoring client yang mencoba terkoneksi ke AP target
- 💣 Auth Flood menggunakan `mdk4`
- 💥 Deauth Attack (opsional jika PMF nonaktif)
- 📈 Statistik real-time jumlah paket & client terdeteksi
- 🔁 Auto restart `mdk4` jika berhenti tiba-tiba
- 📝 Logging aktivitas ke file log otomatis
- ⚙️ Dukungan CLI argument untuk fleksibilitas pengguna

---

## ⚙️ Instalasi

### 1. Install Dependensi Sistem
```bash
sudo apt update
sudo apt install -y python3 python3-pip aircrack-ng mdk4 net-tools
```

### 2. Install Modul Python
```bash
pip3 install scapy
```

### 3. Aktifkan Monitor Mode
Gunakan interface Wi-Fi kamu (contoh: `wlan0`) dan ubah ke mode monitor:
```bash
sudo airmon-ng start wlan0
# Interface akan berubah menjadi wlan0mon (tergantung sistem)
```

---

## 🚀 Cara Menjalankan

### Scan Otomatis SSID & BSSID (mode interaktif)
```bash
sudo python3 wimonaf.py -i wlan0mon
```

### Menentukan Target Manual (tanpa scan)
```bash
sudo python3 wimonaf.py -i wlan0mon -b 94:83:C4:50:38:0C -s "NamaSSID"
```

### Mode Deauth (opsional jika target tidak pakai PMF)
```bash
sudo python3 wimonaf.py -i wlan0mon -b XX:XX:XX:XX:XX:XX -s "SSID Target" --deauth
```

### Tampilkan Versi
```bash
sudo python3 wimonaf.py --version
```

---

## 📁 Output
- Semua aktivitas dicatat otomatis ke file:
  ```
  authlog_YYYYMMDD_HHMMSS.txt
  ```

---

## ⚠️ Catatan Penting
- Tool ini hanya untuk **pengujian keamanan jaringan pribadi**.
- Jangan digunakan terhadap jaringan tanpa izin, karena melanggar hukum di banyak negara.
- Pastikan adapter Wi-Fi kamu mendukung **monitor mode** dan **packet injection**.

---

## 📊 Contoh Output
```
[*] Monitoring client yang mencoba konek ke SSID target...
[Client] 78:E3:5D:D4:9B:E4 mencoba konek ke SSID 'Workshop 08'
[+] Total client terdeteksi: 4

[*] mdk4 masih berjalan | Total paket dikirim: 8000
[!] mdk4 berhenti, mencoba ulang dalam 3 detik...
```

---

## 👤 Penulis
**Nama**: Rizq Osman  
**Tools**: Python, Scapy, mdk4  
**Lisensi**: Open Source (MIT)

---

> Gunakan dengan bijak. Edukasi adalah tujuan utama.
