# Red Inject  ![RedInject Banner](https://img.shields.io/badge/version-1.0.0-red?style=flat-square)  
> Developed by **Aashif M**

A lightweight Python-based web vulnerability scanner for detecting **XSS (Cross-Site Scripting)** and **SQL Injection (SQLi)** vulnerabilities in HTML forms.




## Features

- Crawls the website, extracts and scans all HTML forms.
- Tests for XSS using custom payloads.
- Tests for SQLi using known injection patterns.
- Easy to customize payloads (located in `payloads/` directory).

## Implementation
1. Git Clone
   ``` bash
   git clone https://github.com/aashifm1/Red-Inject.git
   ```
2. Make virtual environment
   ``` bash
   python -m venv venv
   source venv/bin/activate
   ```
3. Install the Requiremnets
   ``` bash
   pip install -r requirements.txt
   ```
4. Run the script
   ``` bash
   python3 redinject.py -h
   ```

### Example Command: python3 redinject.py --depth 2 https://www.example.com

## Outcome 👇
<img src="https://github.com/user-attachments/assets/13cb24b0-809d-4155-83b2-92eea359073d" width="930" />

<img src="https://github.com/user-attachments/assets/a919e940-cdf1-42c7-8467-7a8257532a15" width="930" />

---
