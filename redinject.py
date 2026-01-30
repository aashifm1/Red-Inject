import argparse
import requests
import time
import signal
import sys
import uuid
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from colorama import Fore, Style, init
from pyfiglet import figlet_format


# ------------------ BANNER -----------------

banner = figlet_format("RedInject", font="slant")
lines = banner.splitlines()

# Attach version to the RedInject baseline (second last line)
lines[-2] += " v2.0"

print("\n".join(lines))
print(" (Web Vulnerability Scanner) \n".center(50))


# ------------------ INIT ------------------

init(autoreset=True)

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
})


visited = set()
vulnerabilities = []

RATE_LIMIT = 0.5  # seconds between requests


# ------------------ SIGNAL HANDLER ------------------

def signal_handler(sig, frame):
    print(f"\n{Fore.RED}[!] Scan interrupted by user.")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


# ------------------ HELPERS ------------------

def normalize_url(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

def same_domain(url, target_netloc):
    return urlparse(url).netloc == target_netloc

def load_payloads(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Fore.RED}[!] Failed loading payloads: {e}")
        sys.exit(1)

def safe_request(method, url, **kwargs):
    time.sleep(RATE_LIMIT)
    try:
        return session.request(method, url, timeout=10, **kwargs)
    except requests.RequestException:
        return None


# ------------------ FORM PARSING ------------------

def extract_forms(url):
    res = safe_request("GET", url)
    if not res:
        return []
    soup = BeautifulSoup(res.text, "html.parser")
    return soup.find_all("form")

def get_form_details(form, base_url):
    action = form.get("action")
    method = form.get("method", "get").lower()
    action_url = urljoin(base_url, action) if action else base_url

    inputs = []
    for tag in form.find_all(["input", "textarea", "select"]):
        name = tag.get("name")
        if not name:
            continue
        inputs.append({
            "name": name,
            "type": tag.get("type", "text"),
            "value": tag.get("value", "")
        })

    return action_url, method, inputs


# ------------------ XSS TEST ------------------

def test_xss(action_url, method, inputs):
    marker = f"XSS-{uuid.uuid4().hex}"
    payload = f'"><svg/onload=alert("{marker}")>'

    data = {}
    for inp in inputs:
        data[inp["name"]] = payload

    baseline = safe_request(method.upper(), action_url, params=data if method == "get" else None,
                            data=data if method == "post" else None)
    if not baseline:
        return

    if marker in baseline.text:
        print(f"{Fore.YELLOW}[XSS] Reflected XSS detected → {action_url}")
        vulnerabilities.append({
            "type": "XSS",
            "url": action_url,
            "payload": payload
        })


# ------------------ SQLi TEST ------------------

def test_sqli(action_url, method, inputs):
    true_payload = "' OR '1'='1"
    false_payload = "' OR '1'='2"

    base_data = {inp["name"]: "test" for inp in inputs}

    true_data = base_data.copy()
    false_data = base_data.copy()

    for k in true_data:
        true_data[k] = true_payload
        false_data[k] = false_payload

    res_true = safe_request(method.upper(), action_url,
                            params=true_data if method == "get" else None,
                            data=true_data if method == "post" else None)

    res_false = safe_request(method.upper(), action_url,
                             params=false_data if method == "get" else None,
                             data=false_data if method == "post" else None)

    if not res_true or not res_false:
        return

    if abs(len(res_true.text) - len(res_false.text)) > 50:
        print(f"{Fore.RED}[SQLi] Possible SQL Injection → {action_url}")
        vulnerabilities.append({
            "type": "SQLi",
            "url": action_url,
            "payload": true_payload
        })


# ------------------ CRAWLER ------------------

def crawl(url, target_netloc, depth):
    if depth <= 0:
        return

    normalized = normalize_url(url)
    if normalized in visited:
        return
    visited.add(normalized)

    print(f"{Fore.BLUE}[*] Crawling: {url}")

    res = safe_request("GET", url)
    if not res:
        return

    soup = BeautifulSoup(res.text, "html.parser")

    # Scan forms
    forms = extract_forms(url)
    for form in forms:
        action_url, method, inputs = get_form_details(form, url)
        test_xss(action_url, method, inputs)
        test_sqli(action_url, method, inputs)

    # Crawl links
    for link in soup.find_all("a"):
        href = link.get("href")
        if not href:
            continue
        next_url = urljoin(url, href)
        if same_domain(next_url, target_netloc):
            crawl(next_url, target_netloc, depth - 1)


# ------------------ MAIN ------------------

def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
python3 redinject.py --depth 3 https://example.com

                """)

    parser.add_argument(
        "url",
        help="Target URL (e.g. https://example.com)"
    )

    parser.add_argument(
        "--depth",
        type=int,
        default=2,
        help="Crawling depth (default: 2)"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="RedInject v2.0"
    )

    args = parser.parse_args()

    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https"):
        print(f"{Fore.RED}[ERR] Invalid URL format (use http/https)")
        sys.exit(1)

    print(f"{Fore.CYAN}[INF] Target      : {args.url}")
    print(f"{Fore.CYAN}[INF] Crawl Depth : {args.depth}")

    confirm = input(f"{Fore.YELLOW}[?] Start scan? (y/n): ").lower()
    if confirm != "y":
        print(f"{Fore.YELLOW}[INF] Scan aborted by user")
        sys.exit(0)

    crawl(args.url, parsed.netloc, args.depth)

    print(f"\n{Fore.GREEN}[+] Scan Complete")

    if not vulnerabilities:
        print(f"{Fore.GREEN}[INF] No vulnerabilities found")
        return

    print(f"{Fore.RED}[!] Vulnerabilities Found:\n")
    for v in vulnerabilities:
        print(f" - {v['type']} | {v['url']} | {v['payload']}")

if __name__ == "__main__":
    main()
    
