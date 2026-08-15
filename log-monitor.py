import time
import re
from collections import defaultdict
from pathlib import Path

# --- Configuration ---
LOG_FILE = Path("server_access.log")
FAILED_THRESHOLD = 3
SUSPICIOUS_IPS = set()

# Pre-compiled regex for performance (Human engineer optimization)
SQLI_REGEX = re.compile(r"(--|OR\s+1=1|UNION\s+SELECT|[';])", re.IGNORECASE)
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

failed_attempts = defaultdict(int)

def tail_log(file_path):
    """Generator to yield new lines as they are appended to the log file (efficient tail -f)."""
    if not file_path.exists():
        file_path.touch()
        
    with open(file_path, "r") as f:
        f.seek(0, 2) # Jump to EOF
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.strip()

def analyze():
    print(f"[*] Monitoring log stream: {LOG_FILE.absolute()}")
    print("[*] Defense engine online. Press Ctrl+C to abort.\n")
    
    try:
        for line in tail_log(LOG_FILE):
            if not line:
                continue
            
            # 1. Check for SQL Injection
            if SQLI_REGEX.search(line):
                print(f"[!] ALERT [SQLi]: Potential injection detected -> {line}")
                continue

            # 2. Check for Brute Force patterns
            if "FAILED_LOGIN" in line:
                match = IP_REGEX.search(line)
                if match:
                    ip = match.group(0)
                    failed_attempts[ip] += 1
                    print(f"[-] WARNING [BruteForce]: Failed login from {ip} (Count: {failed_attempts[ip]})")
                    
                    if failed_attempts[ip] >= FAILED_THRESHOLD and ip not in SUSPICIOUS_IPS:
                        SUSPICIOUS_IPS.add(ip)
                        print(f"[X] ACTION [Firewall]: Threshold reached. Blocking IP -> {ip}")
                        # Real-world hook to iptables/ufw would go here

    except KeyboardInterrupt:
        print("\n[*] Monitor stopped by user.")

if __name__ == "__main__":
    analyze()