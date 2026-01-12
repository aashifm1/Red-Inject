# Red Inject  ![RedInject Banner](https://img.shields.io/badge/version-1.0.0-red?style=flat-square)  
> Developed for educational purposes only (use it ethically)

A web vulnerability scanner for detecting **XSS (Cross-Site Scripting)** and **SQLi (SQL Injection)** vulnerabilities in HTML forms.
<img width="800" height="450" alt="vuln-scan-2" src="https://github.com/user-attachments/assets/ab58fb16-38ee-4c86-b278-0a4b1192da0e" />

## Installation
1. Clone the repository
   ``` bash
   git clone https://github.com/aashifm1/Red-Inject.git
   ```
2. Create a virtual environment
   ``` bash
   python -m venv venv
   source venv/bin/activate
   ```
3. Install the dependencies
   ``` bash
   pip install -r requirements.txt
   ```
4. Execution
   ``` bash
   python3 redinject.py --depth 2 https://www.example.com
   ```

## Execution
```bash
python3 redinject.py -h
    ____           ______        _           __
   / __ \___  ____/ /  _/___    (_)__  _____/ /_
  / /_/ / _ \/ __  // // __ \  / / _ \/ ___/ __/
 / _, _/  __/ /_/ // // / / / / /  __/ /__/ /_
/_/ |_|\___/\__,_/___/_/ /_/_/ /\___/\___/\__/
                          /___/

            ( Developed by Aashif M )
usage: redinject.py [-h] [--depth DEPTH] url

RedInject - Simple Web Vulnerability Scanner

positional arguments:
  url            Target URL (e.g., https://example.com)

options:
  -h, --help     show this help message and exit
  --depth DEPTH  Max crawl depth
```

