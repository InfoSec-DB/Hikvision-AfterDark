# ZoomCCTVScanner

[zoomCCTVScanner](https://github.com/InfoSec-DB/pictureher.png?raw=true)

> **A Python-based CCTV reconnaissance and vulnerability scanner for Hikvision devices.**  
> **Part of the Hikvision-AfterDark toolkit.**  

**Version**: 1.0.8 

---

## 🚀 Features

- **ZoomEye Search Support** – Load JSON results from **manual** ZoomEye queries.  
- **Hikvision Vulnerability Detection** – Checks for **CVE-2021-36260** vulnerabilities.  
- **Multithreaded Scanning** – High-speed scanning with parallel processing.  
- **Custom JSON Input** – Scan specific IP/port lists for vulnerabilities.  
- **Tor Support** – Optionally route traffic through **Tor** for anonymity.  
- **Exports Results** – Saves findings to a log file for further analysis.  

---

## 🔥 CVE-2021-36260 - Hikvision Exploit

- **CVE-ID**: [CVE-2021-36260](https://nvd.nist.gov/vuln/detail/CVE-2021-36260)  
- **Severity**: 🔴 Critical (CVSS Score: 9.8)  
- **Vulnerability Type**: Unauthenticated Remote Command Injection  
- **Affected Devices**: Hikvision IP Cameras & NVRs (various models)  
- **Impact**:  
  - Allows **remote attackers** to execute **arbitrary system commands** without authentication.  
  - Exposed devices can be **fully compromised**, **stream hijacked**, or used as **pivot points** in attacks.  
  - Exploit works via **specially crafted HTTP requests** sent to vulnerable devices.  

🔹 **References:**  
- [Hikvision Security Notice](https://www.hikvision.com/en/support/cybersecurity/security-advisory/security-notification-command-injection-vulnerability-in-some-hikvision-products/)  
- [CISA Alert](https://www.cisa.gov/news-events/alerts/2021/09/28/rce-vulnerability-hikvision-cameras-cve-2021-36260)  
- [NVD Database](https://nvd.nist.gov/vuln/detail/CVE-2021-36260)  

---

## 🕵️‍♂️ How to Search for Targets on ZoomEye

Since this scanner **does not use the ZoomEye API**, you must **manually search** on the ZoomEye website and download results as **JSON**.

### **1️⃣ Go to ZoomEye.org and search for this dork:**

```
http.body_hash=="c49ca1932cca63320890e8db87c72ff7" && country=RU && (iconhash="89b932fcc47cf4ca3faadb0cfdef89cf")
```

- This query finds **Hikvision cameras in the United States** with specific fingerprints.  
- Modify the `country=RU` part to target **other countries** if needed.

### **2️⃣ Export results from ZoomEye as a JSON file**

1. After running the search on ZoomEye, click **Export Results**.  
2. Save the exported file (e.g., `results.json`).  

### **3️⃣ Use ZoomCCTVScanner to analyze the JSON file**

Run the scanner to check which cameras are vulnerable:  
```bash
python zoomCCTVScanner.py --file results.json --threads 20 --output vulnerable_cameras.txt
```

---

## ⚙️ Installation & Requirements

1. **Clone the repository**:  
   ```bash
   git clone https://github.com/InfoSec-DB/Hikvision-AfterDark.git
   cd Hikvision-Afterdark/zoomCCTVScanner
   ```
2. **Ensure you have downloaded a ZoomEye JSON file** with the correct format.  
3. **Optional**: If using **Tor**, ensure it is running on **port 9050**.

---

## 🚨 Usage

Run the scanner with a **JSON list of IPs and ports**:  
```bash
python zoomCCTVScanner.py --file results.json --threads 20 --output results.txt
```

### Available Options:
| Argument | Description |
|----------|-------------|
| `--file, -f` | Path to JSON file containing IP/Port data |
| `--output, -o` | Save scan results to a file (default: `hikvision_scan_results.txt`) |
| `--threads, -t` | Number of threads for faster scanning (default: `20`) |

### JSON File Format (`results.json` Example)
```json
{"ip": "192.168.1.1", "port": "80"}
{"ip": "203.0.113.10", "port": "443,8080"}
{"ip": "45.33.32.156", "port": ["80", "554"]}
```

---

## 📌 How It Works

1. **Reads a JSON file** containing IP addresses and ports from **ZoomEye results**.  
2. **Extracts unique IP/Port pairs** and filters Hikvision devices.  
3. **Sends crafted requests** to test if a device is vulnerable.  
4. **Logs findings** and outputs them in a structured format.  
5. **Color-coded console output** for easier interpretation of results.  

✅ **Vulnerable Devices** → Displayed in **green**.  
⚠️ **Secure or Unknown Response** → Displayed in **yellow**.  
❌ **Errors or Failed Connections** → Displayed in **red**.  

---

## 🛡️ Disclaimer

1. **Legal & Ethical Use Only** – This tool is for **authorized security research** and **OSINT purposes**.  
2. **Liability** – The author(s) assume **no responsibility** for misuse or any unlawful activity.  
3. **Respect Privacy** – Do not access systems without explicit permission.  

🔹 **⚠️ WARNING:** Unauthorized access to systems **violates** laws such as the **CFAA (US)** or **Computer Misuse Act (UK)**.

---

## 📜 License

This project is provided **as-is** under the terms of the license you choose. (MIT, GPL, etc.)  
Feel free to adapt or redistribute for ethical purposes.

---

### 🏴‍☠️ Acknowledgments

- **[#AfterDark]** – Original Hikvision scanning concept.  
- **ZoomEye** – OSINT search engine used for reconnaissance.  
- **Tor Project** – Anonymity support for safe scanning.  

---

> **Note:** Always **secure your devices** by disabling unnecessary ports, updating firmware, and following best security practices.
