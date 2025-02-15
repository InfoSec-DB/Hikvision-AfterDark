# Hikvision-AfterDark

> A Python-based Hikvision exploitation and CCTV viewer toolkit, created by [#AfterDark] for **authorized security testing** and **educational purposes** only.  

**Version**: 1.0.0

---

## 🚀 Features

- **Live Feed Previews** – See multiple Hikvision cameras in real-time.  
- **Snapshot Analysis** – Click a feed to open a **zoomable, pannable** snapshot window for detailed inspection.  
- **Tor Integration** – Optionally route traffic via Tor (`--tor`, `--tor-check`).  
- **IP Display** – Shows each camera's resolved IP.  
- **CVE-2021-36260** – Exploits a critical unauthenticated command injection vulnerability in Hikvision devices.

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
   git clone https://github.com/YourUser/Hikvision-AfterDark.git
   cd Hikvision-AfterDark
   ```
2. **Install dependencies** (e.g., `requests`, `PySide6`, `pyfiglet`, `matplotlib`):  
   ```bash
   pip install -r requirements.txt
   ```
   *(Or install them manually if you prefer.)*

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

## 🛡️ Disclaimer

1. **Authorized Testing Only**: This tool is designed for **ethical hacking** and **security research**.  
2. **Liability**: The author(s) assume **no liability** for misuse or damage caused.  
3. **Compliance**: Check local laws and obtain **written permission** before testing any devices you do not own.

---

## 📜 License

This project is provided **as-is** under the terms of the license you choose. (MIT, GPL, etc.)  
Feel free to adapt or redistribute for ethical purposes.

---

### 🏴‍☠️ Acknowledgments

- **[#AfterDark]** – Original exploitation script and ASCII banner concept.  
- **PySide6** – GUI framework.  
- **Requests** – HTTP library.  
- **Tor** – For optional anonymity and safe exploration.  

---

> **Note**: CVE references are for educational context. Always patch or secure devices to the latest firmware to avoid real-world exploits.
