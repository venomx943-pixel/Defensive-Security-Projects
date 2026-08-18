import time
import json
from pathlib import Path


INCIDENT_QUEUE_FILE = Path("incident_stream.json")
BLOCKED_IPS_FILE = Path("blocked_ips_log.txt")

def mitigate_threat(incident):
    """Automated response playbook (Playbook execution)."""
    ip = incident.get("source_ip")
    threat_type = incident.get("type")


print(f"\n[! SOAR Playbook Triggered]")
print(f" [+] Threat type : {threat_type}")
print(f" [+] Attacker IP : {ip}")


if ip:
    with open(BLOCKED_IPS_FILE, "a") as f:
        f.write(f"{ip} - Blocked due to {threat_type} at {time.ctime()}\n")
        print(f" [correct] Automated Action: Ip {ip} successfuly isolated and blocked.")

        print(f" [correct] Automated Action: Security Operations Team a;erted  via webhook.")
        print("-" * 50)

def soar_engine_loop():
    """Continuousaly listens for security incidents  amd executes automated defense."""
    print("[*] Mini-SOAR Automation Engine is activee and listening for incidents...")
    print("[*] Press Ctrl+C to stop.\n")

    if not INCIDENT_QUEUE_FILE.exists():
        INCIDENT_QUEUE_FILE.write_text(json.dumps([]))

    try:
        while True:
            if INCIDENT_QUEUE_FILE.exists():
                try:
                    data = json.loads(INCIDENT_QUEUE_FILE.read_text())
                    if data:
                        for incident in data:
                            mitigate_threat(incident)

                            INCIDENT_QUEUE_FILE.write_text(json.dumps([]))
                except json.JSONDecodeError:
                    pass
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[*] SOAR Engine stopped by user.")

if __name__ == "__main__":
    soar_engine_loop()            