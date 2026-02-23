import os
import time
import hashlib
import smtplib
import logging
import subprocess
import sqlite3
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Thread
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR

# ------------------------------
# Configuration and Global Variables
# ------------------------------

# Logging configuration
logging.basicConfig(filename='hybrid_ids.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

# Email configuration (adjust to your SMTP server details)
EMAIL_HOST = "sandbox.smtp.mailtrap.io"
EMAIL_PORT = 2525
EMAIL_USERNAME = "2c1d5044325903"
EMAIL_PASSWORD = "86b6f78fce1195"
EMAIL_SENDER = "nargiza@example.com"
EMAIL_RECEIVER = "suman@example.com"

# File Integrity Monitoring configuration
MONITOR_FILE = "/etc/passwd"

# Global thresholds and variables

# Reduced IP block duration for testing (40 seconds)
IP_BLOCK_DURATION = 40  
BLOCKED_IPS = {}
ALREADY_BLOCKED = set()  # Once an IP is blocked, it will not be blocked again

DOS_THRESHOLD = 100  # Maximum packets per second considered normal
TRAFFIC_HISTORY = {}  # For DoS detection (stores timestamps per IP)

SCAN_TIME_WINDOW = 5  # Time window (in seconds) for Nmap scan detection
SCAN_THRESHOLD = 10   # Unique destination ports in the window to trigger an alert
SCAN_ATTEMPTS = {}    # Tracks (timestamp, destination port) tuples per source IP

# DNS tunneling detection thresholds
DNS_QUERY_LENGTH_THRESHOLD = 50  # Flag a DNS query if its length exceeds this value
DNS_LABEL_THRESHOLD = 5          # Flag if the query has more than this number of subdomain labels

# SQLite Database Configuration
DB_FILE = 'hybrid_ids.db'

# ------------------------------
# Database Functions
# ------------------------------

def init_db():
    """Initialize the SQLite database and create the alerts table if it doesn't exist."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT,
                ip TEXT,
                message TEXT
            )
        ''')
        conn.commit()
    except Exception as e:
        logging.error(f"Database initialization failed: {e}")
    finally:
        conn.close()

def record_alert(alert_type, ip, message):
    """
    Record an alert event:
      - Log it locally.
      - Send an email alert.
      - Insert a record into the SQLite database.
    """
    log_alert(message)
    send_alert(alert_type, message)
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO alerts (alert_type, ip, message) VALUES (?, ?, ?)",
                       (alert_type, ip, message))
        conn.commit()
    except Exception as e:
        logging.error(f"Failed to insert alert into DB: {e}")
    finally:
        conn.close()

def db_log_info(info_type, ip, message):
    """
    Log an informational event in the database without sending an email.
    Used for events like IP blocking/unblocking.
    """
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO alerts (alert_type, ip, message) VALUES (?, ?, ?)",
                       (info_type, ip, message))
        conn.commit()
    except Exception as e:
        logging.error(f"Failed to insert info log into DB: {e}")
    finally:
        conn.close()

# ------------------------------
# Alerting and Logging Functions
# ------------------------------

def send_alert(subject, message):
    """Send an email alert using the configured SMTP server."""
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))
        
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        
        logging.info(f"[ALERT] Email sent: {subject}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

def log_alert(alert_msg):
    """Log an alert message and print it to the console."""
    logging.info(alert_msg)
    print(alert_msg)

# ------------------------------
# Core IDS Functionalities
# ------------------------------

def get_checksum(file_path):
    """Calculate the SHA-256 checksum of a file."""
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            hasher.update(f.read())
        return hasher.hexdigest()
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return None

def file_integrity_monitor():
    """Monitor file integrity changes (e.g., modifications to /etc/passwd)."""
    previous_hash = get_checksum(MONITOR_FILE)
    log_alert("[INFO] Monitoring file integrity...")
    while True:
        time.sleep(5)
        current_hash = get_checksum(MONITOR_FILE)
        if current_hash and previous_hash and current_hash != previous_hash:
            alert_msg = "[ALERT] File integrity violation detected! /etc/passwd was modified."
            record_alert("File Integrity Alert", "", alert_msg)
            previous_hash = current_hash

def block_ip(ip):
    """
    Block an IP address temporarily using iptables.
    For testing, if an IP has already been blocked once, it will not be blocked again.
    """
    if ip in ALREADY_BLOCKED:
        return
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    BLOCKED_IPS[ip] = time.time()
    ALREADY_BLOCKED.add(ip)
    info_msg = f"[INFO] Blocked IP: {ip} for {IP_BLOCK_DURATION} seconds (testing only, will not re-block)"
    log_alert(info_msg)
    db_log_info("IP Blocked", ip, info_msg)

def unblock_ips():
    """Unblock IP addresses after the block duration expires."""
    while True:
        time.sleep(30)
        current_time = time.time()
        for ip, block_time in list(BLOCKED_IPS.items()):
            if current_time - block_time > IP_BLOCK_DURATION:
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
                del BLOCKED_IPS[ip]
                info_msg = f"[INFO] Unblocked IP: {ip}"
                log_alert(info_msg)
                db_log_info("IP Unblocked", ip, info_msg)

def detect_reverse_shell():
    """
    Detect potential reverse shells.
    Uses netstat output to find established connections with suspicious process names.
    For testing, we now skip only connections on port 22 (and do not skip when 'sshd' is present).
    The pattern includes 'nc', 'bash', 'python', and 'perl'.
    """
    log_alert("[INFO] Monitoring for Reverse Shells...")
    pattern = re.compile(r'\b(?:nc|bash|python|perl)\b')
    while True:
        result = subprocess.run(['netstat', '-antp'],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
        for line in result.stdout.splitlines():
            if "ESTABLISHED" not in line:
                continue
            fields = line.split()
            if len(fields) < 7:
                continue
            local_address = fields[3]
            remote_address = fields[4]
            process_info = fields[6]
            # Skip standard SSH sessions based solely on local port.
            if local_address.endswith(":22"):
                continue
            if pattern.search(line):
                try:
                    ip = remote_address.split(':')[0]
                except IndexError:
                    continue
                alert_msg = f"[ALERT] Possible Reverse Shell Detected: {line}"
                record_alert("Reverse Shell Alert", ip, alert_msg)
                block_ip(ip)
        time.sleep(5)

def detect_nmap_scan(packet):
    """
    Detect Nmap scans by tracking unique destination ports probed by an IP within a short time window.
    """
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        current_time = time.time()
        dport = packet[TCP].dport
        if src_ip not in SCAN_ATTEMPTS:
            SCAN_ATTEMPTS[src_ip] = []
        SCAN_ATTEMPTS[src_ip].append((current_time, dport))
        # Remove entries older than the scan time window.
        SCAN_ATTEMPTS[src_ip] = [(t, p) for (t, p) in SCAN_ATTEMPTS[src_ip] if current_time - t <= SCAN_TIME_WINDOW]
        unique_ports = len(set(p for (t, p) in SCAN_ATTEMPTS[src_ip]))
        if unique_ports > SCAN_THRESHOLD:
            alert_msg = (f"[ALERT] Nmap Scan Detected from {src_ip}! "
                         f"Unique destination ports scanned in last {SCAN_TIME_WINDOW} seconds: {unique_ports}")
            record_alert("Nmap Scan Alert", src_ip, alert_msg)
            block_ip(src_ip)
            SCAN_ATTEMPTS[src_ip] = []

def detect_dos_attack(packet):
    """
    Detect DoS attacks by counting the number of packets per second from a given IP.
    """
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_time = time.time()
        if src_ip not in TRAFFIC_HISTORY:
            TRAFFIC_HISTORY[src_ip] = []
        TRAFFIC_HISTORY[src_ip].append(current_time)
        # Keep only packets from the last 1 second.
        TRAFFIC_HISTORY[src_ip] = [t for t in TRAFFIC_HISTORY[src_ip] if current_time - t <= 1]
        if len(TRAFFIC_HISTORY[src_ip]) > DOS_THRESHOLD:
            alert_msg = (f"[ALERT] DoS Attack Detected from {src_ip}! "
                         f"Packets in last second: {len(TRAFFIC_HISTORY[src_ip])}")
            record_alert("DoS Attack Alert", src_ip, alert_msg)
            block_ip(src_ip)
            TRAFFIC_HISTORY[src_ip] = []

def detect_dns_tunneling(packet):
    """
    Detect suspicious DNS queries that may indicate DNS tunneling.
    Flags queries only if the query is both unusually long and has too many subdomain labels.
    """
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        qname = packet[DNSQR].qname
        if isinstance(qname, bytes):
            qname = qname.decode()
        qname = qname.rstrip('.')  # Remove any trailing dot.
        num_labels = len(qname.split('.'))
        # Require both conditions to reduce false positives.
        if len(qname) > DNS_QUERY_LENGTH_THRESHOLD and num_labels > DNS_LABEL_THRESHOLD:
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            alert_msg = f"[ALERT] Suspicious DNS query detected from {src_ip}: {qname}"
            record_alert("DNS Tunneling Alert", src_ip, alert_msg)

def detect_dns_response_anomalies(packet):
    """
    Detect suspicious DNS responses that might indicate spoofing.
    Flags responses with an unusually low TTL (less than 10 seconds).
    """
    if packet.haslayer(DNS) and packet[DNS].qr == 1:  # DNS response
        if packet[DNS].an and hasattr(packet[DNS].an, 'ttl'):
            ttl = packet[DNS].an.ttl
            if ttl < 10:
                src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
                alert_msg = f"[ALERT] Suspicious DNS response (low TTL: {ttl}) detected from {src_ip}."
                record_alert("DNS Response Anomaly Alert", src_ip, alert_msg)

def process_packet(packet):
    """
    Process each network packet:
      - Check for Nmap scans.
      - Detect DoS attack patterns.
      - Inspect DNS queries for tunneling.
      - Inspect DNS responses for anomalies.
    """
    detect_nmap_scan(packet)
    detect_dos_attack(packet)
    detect_dns_tunneling(packet)
    detect_dns_response_anomalies(packet)

def network_monitor():
    """Monitor network traffic using Scapy's sniff function."""
    log_alert("[INFO] Starting Network Monitoring...")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    # Initialize the SQLite database.
    init_db()
    # Start monitoring threads.
    Thread(target=file_integrity_monitor, daemon=True).start()
    Thread(target=unblock_ips, daemon=True).start()
    Thread(target=detect_reverse_shell, daemon=True).start()
    Thread(target=network_monitor, daemon=True).start()
    
    log_alert("[INFO] Hybrid IDS is running...")
    while True:
        time.sleep(60)
