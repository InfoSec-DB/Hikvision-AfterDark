# Hikvision-AfterDark

> **A Python-based Hikvision exploitation, reconnaissance, and CCTV viewer toolkit.**  
> **Created by [#AfterDark] for authorized security testing and OSINT research.**  

**Version**: 1.0.0  

---

## 🎯 About

**Hikvision-AfterDark** is a **comprehensive toolkit** for **CCTV reconnaissance, live monitoring, and vulnerability assessment**.  
It includes **multiple tools** designed to **locate, analyze, and exploit** exposed Hikvision cameras across the internet.  

💡 **This toolkit is ideal for:**  
- **Red Teaming** – Identify and exploit exposed CCTV cameras in real time.  
- **OSINT & Reconnaissance** – Gather intelligence on unsecured surveillance systems.  
- **Vulnerability Research** – Test for known security flaws, including **CVE-2021-36260**.  

🚨 **For ethical use only! Unauthorized access to devices you do not own is illegal.**  

---

## 🚀 Features

- **Live Feed Previews** – See multiple Hikvision cameras in real-time.  
- **Snapshot Analysis** – Click a feed to open a **zoomable, pannable** snapshot window for detailed inspection.  
- **Tor Integration** – Optionally route traffic via Tor (`--tor`, `--tor-check`).  
- **IP Display** – Shows each camera's resolved IP.  
- **CVE-2021-36260 Exploit** – Identifies vulnerable Hikvision devices.  
- **Shodan & ZoomEye Support** – Scan for public CCTV cameras worldwide.  

---

## 🔥 CVE-2021-36260 - Hikvision Exploit

- **CVE-ID**: [CVE-2021-36260](https://nvd.nist.gov/vuln/detail/CVE-2021-36260)  
- **Severity**: 🔴 Critical (CVSS Score: 9.8)  
- **Vulnerability Type**: Unauthenticated Remote Command Injection  
- **Affected Devices**: Hikvision IP Cameras & NVRs (specific models)  
- **Impact**: This exploit allows remote attackers to **execute arbitrary system commands** on affected devices **without authentication**.  
- **Technical Details**:  
  - The vulnerability exists due to **improper input validation** in the web server component.  
  - Attackers can send a **crafted HTTP request** with a **malicious payload** to execute commands.  
  - If exploited, it can **compromise live video feeds**, **disable security systems**, or **pivot into internal networks**.  

🔹 **References:**  
- [Hikvision Security Notice](https://www.hikvision.com/en/support/cybersecurity/security-advisory/security-notification-command-injection-vulnerability-in-some-hikvision-products/)  
- [CISA Alert](https://www.cisa.gov/news-events/alerts/2021/09/28/rce-vulnerability-hikvision-cameras-cve-2021-36260)  
- [NVD Database](https://nvd.nist.gov/vuln/detail/CVE-2021-36260)  

---

## ⚙️ Installation & Requirements

1. **Clone this repo**:  
   ```bash
   git clone https://github.com/InfoSec-DB/Hikvision-AfterDark.git
   cd Hikvision-AfterDark
   ```

2. **Install dependencies** (e.g., `requests`, `PySide6`, `pyfiglet`, `matplotlib`):  
   ```bash
   pip install -r requirements.txt
   ```

3. **Optional**: If you plan to use Tor, ensure **Tor** is running locally on port `9050`.

---

## 🚨 Usage

1. **Run the tool**:  
   ```bash
   python cctv_new.py --file cameras.txt --tor --tor-check
   ```
   - `--file, -f`: Path to the file containing camera URLs  
   - `--refresh, -r`: Refresh interval in seconds (default: `1.0`)  
   - `--max, -m`: Max number of camera feeds (default: `10`)  
   - `--tor, -t`: Use Tor network for camera feeds  
   - `--tor-check`: Check if Tor is running, then exit  

2. **Click on a camera feed** in the main window to open a **snapshot** in a new window:
   - **Zoom** with your mouse wheel.  
   - **Pan** by dragging.  
   - **Multiple** snapshot windows can be opened simultaneously.  

3. **Traffic Monitor**: If `--tor` is used (and Tor is running), the tool will also open a **Tor Traffic Monitor** window. Otherwise, a **normal** traffic monitor is shown.  

---

## 🔎 Additional Tools in This Repository

Hikvision-AfterDark also includes powerful scanning tools to **find** vulnerable cameras worldwide.

### 🛰️ [ZoomCCTVScanner - ZoomEye OSINT Recon](https://github.com/InfoSec-DB/Hikvision-AfterDark/tree/main/zoomCCTVScanner)

- **Finds Hikvision cameras via ZoomEye searches.**  
- **Uses dork queries** to locate exposed CCTV feeds.  
- **Loads ZoomEye JSON exports** to scan for vulnerabilities.  
- **Ideal for OSINT, intelligence gathering, and penetration testing.**  

💡 **How to use:**  
1. Search on **ZoomEye.org** using:  
   ```
   http.body_hash=="c49ca1932cca63320890e8db87c72ff7" && country=RU && (iconhash="89b932fcc47cf4ca3faadb0cfdef89cf")
   ```
2. Export results as **JSON**.  
3. Run the scanner:  
   ```bash
   python zoomCCTVScanner.py --file results.json --threads 20 --output vulnerable_cameras.txt
   ```

---

### 🌍 [Hikvision-ShodanScanner - Shodan Hikvision Scanner](https://github.com/InfoSec-DB/Hikvision-AfterDark/tree/main/Hikvision-ShodanScanner)

- **Finds Hikvision cameras using Shodan's API.**  
- **Extracts IP addresses & ports** of potential targets.  
- **Automatically tests if cameras are vulnerable.**  
- **Exports results for further analysis.**  

💡 **How to use:**  
```bash
python shodan_scanner.py --api YOUR_SHODAN_API_KEY --country RU --output results.txt --verbose
```

**Example query to find exposed Hikvision cameras:**  
```bash
python shodan_scanner.py --api YOUR_SHODAN_API_KEY --country US --page 2 --output vulnerable_cameras.txt
```

---

## 🛡️ Disclaimer

1. **Authorized Testing Only**: This toolkit is designed for **ethical hacking** and **security research**.  
2. **Liability**: The author(s) assume **no liability** for misuse or damage caused.  
3. **Compliance**: Check local laws and obtain **written permission** before testing any devices you do not own.  

🚨 **Unauthorized access to systems is illegal!**

---

## 📜 License

This project is provided **as-is** under the terms of the license you choose. (MIT, GPL, etc.)  
Feel free to adapt or redistribute for ethical purposes.

---

### 🏴‍☠️ Acknowledgments

- **[#AfterDark]** – Original exploitation scripts and OSINT toolkit.  
- **PySide6** – GUI framework for the live CCTV viewer.  
- **Requests** – HTTP library for interacting with camera feeds.  
- **ZoomEye & Shodan** – OSINT search engines used for reconnaissance.  
- **Tor Project** – Anonymity support for safe scanning.  

---

> **Note**: CVE references are for educational context. Always patch or secure devices to avoid real-world exploits.
