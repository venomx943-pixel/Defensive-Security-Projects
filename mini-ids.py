from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

# --- Configuration ---
SCAN_THRESHOLD = 15
TIME_WINDOW = 5

# Tracking dictionaries (IP -> List of timestamps)
tcp_scan_tracker = defaultdict(list)
flagged_attackers = set()

def process_packet(packet):
    """Callback function executed on every captured network packet."""
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return
        
    src_ip = packet[IP].src
    tcp_flags = packet[TCP].flags
    
    # Target SYN flags typically used in stealth/connect port scanning (Flag 'S')
    if tcp_flags == 'S':
        current_time = time.time()
        
        # Keep only timestamps within the rolling time window (Memory efficiency)
        timestamps = tcp_scan_tracker[src_ip]
        timestamps[:] = [t for t in timestamps if current_time - t < TIME_WINDOW]
        
        timestamps.append(current_time)
        
        # Check threshold and alert
        if len(timestamps) > SCAN_THRESHOLD and src_ip not in flagged_attackers:
            flagged_attackers.add(src_ip)
            print(f"[!] ALERT [Port Scan]: Reconnaissance detected from {src_ip} ({len(timestamps)} SYN packets in {TIME_WINDOW}s)")
            # Real-world defense hook: Drop traffic via iptables / netfilter

def start_ids():
    print("[*] Mini-IDS Network Sniffer initializing...")
    print("[*] Listening for suspicious TCP patterns. Press Ctrl+C to exit.\n")
    
    try:
        # Sniff only TCP packets to reduce CPU overhead
        sniff(filter="tcp", prn=process_packet, store=False)
    except PermissionError:
        print("[!] ERROR: Packet sniffing requires root / Administrator privileges.")
    except KeyboardInterrupt:
        print("\n[*] IDS stopped by user.")

if __name__ == "__main__":
    start_ids()