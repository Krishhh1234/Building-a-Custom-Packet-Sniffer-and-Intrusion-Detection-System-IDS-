import datetime
import re
import platform
from scapy.all import sniff

# Global variables for alert logging
alert_log_file = "alerts.log"
traffic_log_file = "traffic_log.txt"

# Clear previous logs (if any)
with open(alert_log_file, "w"), open(traffic_log_file, "w"):
    pass

def detect_malicious(packet):
    """Detects malicious patterns in packet payloads and logs alerts."""
    if packet.haslayer('Raw'):
        payload = packet['Raw'].load.decode(errors='ignore')
        
        # List of regex patterns to detect malicious traffic
        patterns = [
            r"' OR '1'='1",  # SQL Injection pattern
            r"<script>",     # XSS pattern
            r"nmap",         # Port scanning tool detection
        ]

        for pattern in patterns:
            if re.search(pattern, payload):
                alert_message = f"[{datetime.datetime.now()}] ALERT: Malicious Pattern Detected: {pattern}\n"
                print(alert_message.strip())
                with open(alert_log_file, "a") as alert_log:
                    alert_log.write(alert_message)
                break  # Avoid multiple alerts for the same packet

def packet_callback(packet):
    """Logs all captured packets and passes them to the intrusion detection function."""
    log_message = f"[{datetime.datetime.now()}] Packet Captured: {packet.summary()}\n"
    with open(traffic_log_file, "a") as log:
        log.write(log_message)
    
    # Pass the packet to the malicious detection function
    detect_malicious(packet)

def get_interface():
    """Detects the appropriate network interface based on the operating system."""
    os_type = platform.system()
    if os_type == "Windows":
        return "Wi-Fi"
    elif os_type == "Linux":
        return "eth0"
    else:  # macOS
        return "en0"

def generate_report():
    """Generates a summary report of all alerts."""
    try:
        with open(alert_log_file, "r") as log:
            alerts = log.readlines()
        
        report = f"Intrusion Detection Report\n{'='*30}\n"
        report += f"Total Alerts: {len(alerts)}\n\n"
        report += "".join(alerts)
        
        with open("report.txt", "w") as report_file:
            report_file.write(report)

        print("\nReport generated: report.txt")
    except FileNotFoundError:
        print("\nNo alerts found. Report not generated.")

def main():
    """Main function to run the packet sniffer and IDS."""
    interface = get_interface()
    print(f"[*] Starting packet capture on interface: {interface}")
    
    try:
        sniff(iface=interface, prn=packet_callback, store=0)
    except PermissionError:
        print("[!] Permission denied. Please run the script with elevated privileges (sudo).")
    except KeyboardInterrupt:
        print("\n[!] Packet capture stopped. Generating report...")
        generate_report()

if __name__ == "__main__":
    main()
