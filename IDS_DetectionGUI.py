import os
import time
import hashlib
import smtplib
import logging
import subprocess
import sqlite3
import re
import threading
import queue
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Thread
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR, AsyncSniffer

# Logging configuration
logging.basicConfig(filename='hybrid_ids.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

# Email configuration
EMAIL_HOST = "sandbox.smtp.mailtrap.io"
EMAIL_PORT = 2525
EMAIL_USERNAME = "2c1d5044325903"
EMAIL_PASSWORD = "86b6f78fce1195"
EMAIL_SENDER = "nargiza@example.com"
EMAIL_RECEIVER = "suman@example.com"

# File Integrity Monitoring configuration
MONITOR_FILE = "/etc/passwd"

# Global thresholds and variables
IP_BLOCK_DURATION = 40  
BLOCKED_IPS = {}
ALREADY_BLOCKED = set()
DOS_THRESHOLD = 100
TRAFFIC_HISTORY = {}
SCAN_TIME_WINDOW = 5
SCAN_THRESHOLD = 10
SCAN_ATTEMPTS = {}
DNS_QUERY_LENGTH_THRESHOLD = 50
DNS_LABEL_THRESHOLD = 5
DB_FILE = 'hybrid_ids.db'
stop_event = threading.Event()
alert_queue = queue.Queue()

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
    """Log an informational event in the database without sending an email."""
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
    """Log an alert message, print it, and add it to the GUI alert queue."""
    logging.info(alert_msg)
    print(alert_msg)
    if alert_msg.startswith("[ALERT]"):
        alert_queue.put(("alert", alert_msg))
    else:
        alert_queue.put(("info", alert_msg))

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
    """Monitor file integrity changes."""
    previous_hash = get_checksum(MONITOR_FILE)
    log_alert("[INFO] Monitoring file integrity...")
    while not stop_event.is_set():
        time.sleep(5)
        current_hash = get_checksum(MONITOR_FILE)
        if current_hash and previous_hash and current_hash != previous_hash:
            alert_msg = "[ALERT] File integrity violation detected! /etc/passwd was modified."
            record_alert("File Integrity Alert", "", alert_msg)
            previous_hash = current_hash

def block_ip(ip):
    """
    Block an IP address temporarily using iptables.
    If an IP has already been blocked, it will not be blocked again.
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
    while not stop_event.is_set():
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
    Detect potential reverse shells using netstat to find established connections
    with suspicious process names.
    """
    log_alert("[INFO] Monitoring for Reverse Shells...")
    pattern = re.compile(r'\b(?:nc|bash|python|perl)\b')
    while not stop_event.is_set():
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
    """Detect Nmap scans by tracking unique destination ports probed by an IP."""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        current_time = time.time()
        dport = packet[TCP].dport
        if src_ip not in SCAN_ATTEMPTS:
            SCAN_ATTEMPTS[src_ip] = []
        SCAN_ATTEMPTS[src_ip].append((current_time, dport))
        SCAN_ATTEMPTS[src_ip] = [(t, p) for (t, p) in SCAN_ATTEMPTS[src_ip] if current_time - t <= SCAN_TIME_WINDOW]
        unique_ports = len(set(p for (t, p) in SCAN_ATTEMPTS[src_ip]))
        if unique_ports > SCAN_THRESHOLD:
            alert_msg = (f"[ALERT] Nmap Scan Detected from {src_ip}! "
                         f"Unique destination ports scanned in last {SCAN_TIME_WINDOW} seconds: {unique_ports}")
            record_alert("Nmap Scan Alert", src_ip, alert_msg)
            block_ip(src_ip)
            SCAN_ATTEMPTS[src_ip] = []

def detect_dos_attack(packet):
    """Detect DoS attacks by counting packets per second from a given IP."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        current_time = time.time()
        if src_ip not in TRAFFIC_HISTORY:
            TRAFFIC_HISTORY[src_ip] = []
        TRAFFIC_HISTORY[src_ip].append(current_time)
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
    Flags queries that are unusually long and have too many subdomain labels.
    """
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        qname = packet[DNSQR].qname
        if isinstance(qname, bytes):
            qname = qname.decode()
        qname = qname.rstrip('.')
        num_labels = len(qname.split('.'))
        if len(qname) > DNS_QUERY_LENGTH_THRESHOLD and num_labels > DNS_LABEL_THRESHOLD:
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            alert_msg = f"[ALERT] Suspicious DNS query detected from {src_ip}: {qname}"
            record_alert("DNS Tunneling Alert", src_ip, alert_msg)

def detect_dns_response_anomalies(packet):
    """
    Detect suspicious DNS responses with an unusually low TTL (less than 10 seconds).
    """
    if packet.haslayer(DNS) and packet[DNS].qr == 1:
        if packet[DNS].an and hasattr(packet[DNS].an, 'ttl'):
            ttl = packet[DNS].an.ttl
            if ttl < 10:
                src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
                alert_msg = f"[ALERT] Suspicious DNS response (low TTL: {ttl}) detected from {src_ip}."
                record_alert("DNS Response Anomaly Alert", src_ip, alert_msg)

def process_packet(packet):
    """Process network packets for scans, DoS, DNS tunneling, and DNS anomalies."""
    detect_nmap_scan(packet)
    detect_dos_attack(packet)
    detect_dns_tunneling(packet)
    detect_dns_response_anomalies(packet)

try:
    from PIL import Image, ImageTk
except ImportError:
    Image = None
    ImageTk = None

import tkinter as tk
from tkinter import scrolledtext

class IDS_GUI:
    def __init__(self, root):
        self.root = root
        root.title("Hybrid IDS Dashboard")
        root.geometry("1000x700")
        root.resizable(False, False)
        
        header_frame = tk.Frame(root, bg="darkblue", height=100)
        header_frame.pack(fill=tk.X)
        
        title_label = tk.Label(header_frame, text="Hybrid IDS Dashboard",
                               font=("Helvetica", 24, "bold"),
                               fg="white", bg="darkblue")
        title_label.pack(side=tk.LEFT, padx=10, pady=10)
        
        if Image and ImageTk:
            try:
                logo_image = Image.open("ids_logo.png").resize((80, 80))
                self.logo = ImageTk.PhotoImage(logo_image)
                logo_label = tk.Label(header_frame, image=self.logo, bg="darkblue")
                logo_label.pack(side=tk.RIGHT, padx=10)
            except Exception as e:
                print("Image not loaded:", e)
        
        control_frame = tk.Frame(root)
        control_frame.pack(fill=tk.X, pady=10)
        
        self.start_button = tk.Button(control_frame, text="Start IDS",
                                      font=("Helvetica", 14), command=self.start_ids,
                                      bg="green", fg="white", width=12)
        self.start_button.pack(side=tk.LEFT, padx=10)
        
        self.stop_button = tk.Button(control_frame, text="Stop IDS",
                                     font=("Helvetica", 14), command=self.stop_ids,
                                     bg="red", fg="white", width=12, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=10)
        
        self.clear_button = tk.Button(control_frame, text="Clear Screen",
                                      font=("Helvetica", 14), command=self.clear_screen,
                                      bg="orange", fg="white", width=12)
        self.clear_button.pack(side=tk.LEFT, padx=10)
        
        self.status_label = tk.Label(control_frame, text="Status: Stopped",
                                     font=("Helvetica", 14))
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        self.view_db_logs_button = tk.Button(control_frame, text="View DB Logs",
                                             font=("Helvetica", 14), command=self.view_db_logs,
                                             bg="blue", fg="white", width=14)
        self.view_db_logs_button.pack(side=tk.LEFT, padx=10)
        
        self.view_logfile_button = tk.Button(control_frame, text="View Log File",
                                             font=("Helvetica", 14), command=self.view_logfile,
                                             bg="blue", fg="white", width=14)
        self.view_logfile_button.pack(side=tk.LEFT, padx=10)
        
        self.log_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Helvetica", 12))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.log_text.configure(state=tk.DISABLED)
        self.log_text.tag_config("alert", foreground="red")
        self.log_text.tag_config("info", foreground="black")
        
        self.update_log()
        self.ids_threads = []
        self.sniffer = None

    def start_ids(self):
        stop_event.clear()
        self.ids_threads = []
        
        t1 = Thread(target=file_integrity_monitor, daemon=True)
        self.ids_threads.append(t1)
        t2 = Thread(target=detect_reverse_shell, daemon=True)
        self.ids_threads.append(t2)
        t3 = Thread(target=unblock_ips, daemon=True)
        self.ids_threads.append(t3)
        
        self.sniffer = AsyncSniffer(prn=process_packet, store=False)
        self.sniffer.start()
        
        for t in self.ids_threads:
            t.start()
            
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Status: Running")
        log_alert("[INFO] IDS Started.")

    def stop_ids(self):
        stop_event.set()
        if self.sniffer:
            self.sniffer.stop()
        for t in self.ids_threads:
            t.join(timeout=1)
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Stopped")
        log_alert("[INFO] IDS Stopped.")

    def clear_screen(self):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def update_log(self):
        try:
            while True:
                item = alert_queue.get_nowait()
                if isinstance(item, tuple):
                    level, msg = item
                else:
                    level = "alert" if item.startswith("[ALERT]") else "info"
                    msg = item
                self.log_text.configure(state=tk.NORMAL)
                self.log_text.insert(tk.END, msg + "\n", level)
                self.log_text.configure(state=tk.DISABLED)
                self.log_text.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(100, self.update_log)

    def view_db_logs(self):
        db_log_window = tk.Toplevel(self.root)
        db_log_window.title("Database Logs")
        db_log_window.geometry("800x600")
        text_area = scrolledtext.ScrolledText(db_log_window, wrap=tk.WORD, font=("Helvetica", 12))
        text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
            rows = cursor.fetchall()
            for row in rows:
                try:
                    log_entry = (f"ID: {row[0]} | Time: {row[1]} | Type: {row[2]} | "
                                 f"IP: {row[3]} | Message: {row[4]}\n")
                except IndexError:
                    log_entry = f"Row: {row}\n"
                text_area.insert(tk.END, log_entry)
            text_area.configure(state=tk.DISABLED)
        except Exception as e:
            text_area.insert(tk.END, f"Error retrieving logs: {e}")
        finally:
            conn.close()

    def view_logfile(self):
        log_file_window = tk.Toplevel(self.root)
        log_file_window.title("Log File Viewer")
        log_file_window.geometry("800x600")
        text_area = scrolledtext.ScrolledText(log_file_window, wrap=tk.WORD, font=("Helvetica", 12))
        text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        try:
            with open("hybrid_ids.log", "r") as f:
                content = f.read()
                text_area.insert(tk.END, content)
            text_area.configure(state=tk.DISABLED)
        except Exception as e:
            text_area.insert(tk.END, f"Error opening log file: {e}")

if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    app = IDS_GUI(root)
    root.mainloop()
