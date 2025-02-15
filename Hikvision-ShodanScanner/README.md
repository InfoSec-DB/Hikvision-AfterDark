# Hikvision-ShodanScanner

> **A Python-based reconnaissance and vulnerability scanner for Hikvision cameras using Shodan.**  
> **Part of the Hikvision-AfterDark toolkit.**  

**Version**: 1.0.8 

---

## 🎯 About

**Hikvision-ShodanScanner** is a **powerful OSINT tool** designed to scan and analyze exposed Hikvision cameras using **Shodan**. This scanner helps security researchers identify **unauthenticated public cameras** that may be **vulnerable** to remote exploitation.  

Whether for **security auditing, red team operations, or reconnaissance**, this tool automates **Hikvision camera detection** via **Shodan queries** and checks for **CVE-2021-36260** vulnerability.  

🚨 **This tool is for legal and ethical security research only.** Unauthorized access to systems you do not own is strictly prohibited.  

---

## 🚀 Features

- **CCTV Recon & OSINT** – Locate exposed Hikvision cameras worldwide.  
- **Shodan API Integration** – Automates searching for public CCTV cameras.  
- **Hikvision Vulnerability Detection** – Checks for **CVE-2021-36260** vulnerabilities.  
- **Multithreaded Scanning** – High-speed analysis with parallel processing.  
- **Verbose Logging** – Debug mode available for deeper insights.  
- **Export Results** – Saves vulnerable camera details to a log file.  

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

## ⚙️ Installation & Requirements

1. **Clone the repository**:  
   ```bash
   git clone https://github.com/InfoSec-DB/Hikvision-AfterDark.git
   cd Hikvision-Afterdark/Hikvision-ShodanScanner
   ```

2. **Obtain a Shodan API Key** from [Shodan.io](https://www.shodan.io/)  
3. **Optional**: If using **Tor**, ensure it is running on **port 9050**.

---

## 🚨 Usage

Run the scanner with your **Shodan API key**:  
```bash
python shodan_scanner.py --api YOUR_SHODAN_API_KEY --country RU --output results.txt --verbose
```

### Available Options:
| Argument | Description |
|----------|-------------|
| `--api` | Your Shodan API key (required) |
| `--country` | Target country (default: RU) |
| `--output, -o` | Save scan results to a file (default: `hikvision_scan_results.txt`) |
| `--page, -p` | Number of Shodan result pages to process (default: `1`) |
| `--verbose` | Enable verbose logging for debugging |

### Example Query

```bash
python shodan_scanner.py --api YOUR_SHODAN_API_KEY --country US --page 2 --output vulnerable_cameras.txt
```

💡 **Tip**: Increase `--page` to scan more results, but be mindful of **Shodan API limits**.

---

## 📌 How It Works

1. **Queries Shodan** for exposed Hikvision cameras in a given **country**.  
2. **Extracts unique IP/Port pairs** from the search results.  
3. **Attempts to access the camera snapshot endpoint** for vulnerability testing.  
4. **Logs results** and outputs the list of vulnerable devices.  

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
- **Shodan.io** – OSINT search engine powering the queries.  
- **Tor Project** – Anonymity support for safe scanning.  

---

> **Note:** Always **secure your devices** by disabling unnecessary ports, updating firmware, and following best security practices.
