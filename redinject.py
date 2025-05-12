import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init
from pyfiglet import figlet_format
import signal
import sys
import os

# Initialize Colorama
init(autoreset=True)

# Tool Banner
print(figlet_format("RedInject", font="slant"))
print("( Developed by Aashif M )".center(50))

# Global state
visited = set()
vuln_details = []
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
})

def signal_handler(sig, frame):
    print(f"\n{Fore.RED}[!] Scan terminated by user.{Style.RESET_ALL}")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def is_valid(url):
    parsed = urlparse(url)
    return parsed.scheme in ["http", "https"]

def get_forms(url):
    try:
        res = session.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Failed to get forms from {url}: {e}")
        return []

def load_payloads(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Payload file not found: {file_path}")
        return []

def test_xss(url, form, payloads):
    action = form.get("action")
    post_url = urljoin(url, action)
    method = form.get("method", "get").lower()
    inputs = form.find_all(["input", "textarea"])

    for payload in payloads:
        data = {}
        for input_tag in inputs:
            name = input_tag.get("name")
            if name and input_tag.get("type") not in ("submit", "hidden"):
                data[name] = payload

        try:
            if method == "post":
                res = session.post(post_url, data=data, timeout=10)
            else:
                res = session.get(post_url, params=data, timeout=10)

            if payload in res.text or "<script>" in res.text.lower():
                print(f"{Fore.YELLOW}[XSS] Vulnerable: {post_url} | Payload: {payload}")
                vuln_details.append((post_url, "XSS", payload))
                break
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] XSS test error: {e}")

def test_sqli(url, form, payloads):
    action = form.get("action")
    post_url = urljoin(url, action)
    method = form.get("method", "get").lower()
    inputs = form.find_all("input")

    for payload in payloads:
        data = {}
        for input_tag in inputs:
            name = input_tag.get("name")
            if name and input_tag.get("type") not in ("submit", "hidden"):
                data[name] = payload

        try:
            if method == "post":
                res = session.post(post_url, data=data, timeout=10)
            else:
                res = session.get(post_url, params=data, timeout=10)

            if any(err in res.text.lower() for err in ["sql", "syntax", "mysql", "error", "warning"]):
                print(f"{Fore.RED}[SQLi] Vulnerable: {post_url} | Payload: {payload}")
                vuln_details.append((post_url, "SQLi", payload))
                break
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] SQLi test error: {e}")

def crawl(url, max_depth=2):
    if max_depth == 0 or url in visited:
        return
    visited.add(url)

    print(f"{Fore.BLUE}[*] Crawling: {url}")

    try:
        res = session.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")

        forms = get_forms(url)
        xss_payloads = load_payloads("payloads/xss_pl.txt")
        sqli_payloads = load_payloads("payloads/sqli_pl.txt")

        for form in forms:
            test_xss(url, form, xss_payloads)
            test_sqli(url, form, sqli_payloads)

        for a_tag in soup.find_all("a"):
            href = a_tag.get("href")
            if href:
                full_url = urljoin(url, href)
                if is_valid(full_url):
                    crawl(full_url, max_depth - 1)

    except requests.RequestException as e:
        print(f"{Fore.RED}[!] Crawl error: {e}")

def main():
    parser = argparse.ArgumentParser(description="RedInject - Simple Web Vulnerability Scanner")
    parser.add_argument("url", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--depth", type=int, default=2, help="Max crawl depth")
    args = parser.parse_args()

    if not is_valid(args.url):
        print(f"{Fore.RED}[!] Invalid URL.")
        sys.exit(1)

    confirm = input(f"{Fore.YELLOW}[?] Start scanning {args.url}? (y/n): ").lower()
    if confirm != 'y':
        print(f"{Fore.CYAN}[i] Scan cancelled.")
        sys.exit(0)

    crawl(args.url, args.depth)

    print(f"\n{Fore.GREEN}[+] Vulnerabilities Found:")
    for url, vuln_type, payload in vuln_details:
        print(f" - {url} | {vuln_type} | Payload: {payload}")

if __name__ == "__main__":
    main()
