# Red Inject  ![RedInject Banner](https://img.shields.io/badge/Version-2.0-red?style=flat-square)  
A web vulnerability scanner for detecting **XSS (Cross-Site Scripting)** and **SQLi (SQL Injection)** vulnerabilities.
> Build for educational purposes only

<img width="800" height="450" alt="result" src="https://github.com/user-attachments/assets/9ced555e-4672-4638-909a-d0d5b8b16f77" />

## Installation
Clone the repository
   ``` bash
   git clone https://github.com/aashifm1/Red-Inject.git
   cd Red-Inject
   ```

Create a virtual environment
   ``` bash
   python3 -m venv venv
   source venv/bin/activate
   ```
Install the dependencies
   ``` bash
   pip3 install -r requirements.txt
   ```


## Execution
```bash
-$ python3 redinject.py -h
    ____           ______        _           __
   / __ \___  ____/ /  _/___    (_)__  _____/ /_
  / /_/ / _ \/ __  // // __ \  / / _ \/ ___/ __/
 / _, _/  __/ /_/ // // / / / / /  __/ /__/ /_
/_/ |_|\___/\__,_/___/_/ /_/_/ /\___/\___/\__/   v2.0
                          /___/
         (Web Vulnerability Scanner)
usage: redinject.py [-h] [--depth DEPTH] [--version] url

positional arguments:
  url            Target URL (e.g. https://example.com)

options:
  -h, --help     show this help message and exit
  --depth DEPTH  Crawling depth (default: 2)
  --version      show program's version number and exit

Examples:
  python3 redinject.py --depth 3 https://example.com

```

