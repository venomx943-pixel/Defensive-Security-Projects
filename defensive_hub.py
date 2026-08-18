import json
from pathlib import Path

INCIDENT_QUEUE_FILE = Path("incident_stream.json")

def send_to_soar_engine(incident_type, source_ip):
    """Bridges any security tool alert directly to the SOAR automation queue."""
    incident = {
        "type": incident_type,
        "source_ip": source_ip
    
    }

    queue = []
    if INCIDENT_QUEUE_FILE.exists():
        try:
            queue = json.loads(INCIDENT_QUEUE_FILE.read_text())
        except json.JSONDecodeError:
            queue = []

    queue.append(incident)
    INCIDENT_QUEUE_FILE.write_text(json.dumps(queue, indent=4))
    print(f"[Hub] Dispatched alert [{incident_type}] from {source_ip} to SOAR engine.")

if __name__ == "__main__":
    print("[*] Defensive Security Hub Initialized.")
    print("[*] Simulating integrated alert trigger...")

    send_to_soar_engine("ADVANCED_SQLI_ATTACK", "203.0.113.42")

    print("[*] Check your 'incident_stream.json' and active SOAR engine to watch automated mitigation!")
            