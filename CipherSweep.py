import socket
import nmap
import requests
import threading
import concurrent.futures
import time
import re
import subprocess
from tkinter import *
from tkinter import ttk, messagebox, scrolledtext, filedialog
from datetime import datetime
import webbrowser
from PIL import Image, ImageTk
import sv_ttk


class CipherSweepGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CipherSweep- Vulnerability Scanner")
        self.root.geometry("1000x700")
        self.root.minsize(900, 600)

        sv_ttk.set_theme("dark")

        # Configuration
        self.timeout = 2
        self.max_threads = 30
        self.payloads = self.load_payloads("sql_payloads.txt")
        self.xss_payloads = self.load_payloads("xss_payloads.txt")
        self.scan_active = False
        self.stop_event = threading.Event()

        self.create_styles()

        self.set_window_icon()

        self.create_widgets()
        self.create_menu()

    def create_styles(self):
        style = ttk.Style()
        style.configure('TButton', font=('Segoe UI', 10))
        style.configure('Title.TLabel', font=('Segoe UI', 18, 'bold'))
        style.configure('Subtitle.TLabel', font=('Segoe UI', 12))
        style.configure('Status.TLabel', font=('Segoe UI', 9))

    def set_window_icon(self):
        try:
            self.root.iconbitmap('icon.ico')
        except:
            try:
                img = PhotoImage(file='icon.png')
                self.root.tk.call('wm', 'iconphoto', self.root._w, img)
            except:
                pass  # Icon not essential

    def load_payloads(self, filename):
        default_sqli = ["'", "\"", "1=1", "1=2",
                        "' OR '1'='1", "' OR 1=1--", "' OR ''='"]
        default_xss = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                       "<svg/onload=alert(1)>", "<body onload=alert('XSS')>"]

        try:
            with open(filename, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return default_sqli if "sql" in filename else default_xss

    def create_menu(self):
        menubar = Menu(self.root)

        file_menu = Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Scan", command=self.reset_scan)
        file_menu.add_command(label="Save Report", command=self.save_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

    def show_docs(self):
        docs = """
        CipherSweep Pro Documentation
        
        1. Enter target (IP, hostname, or URL)
        2. Set port range (default 1-1024)
        3. Select scan options
        4. Click Start Scan
        
        Note: Always get proper authorization before scanning.
        """
        messagebox.showinfo("Documentation", docs)

    def show_about(self):
        about = """
        CipherSweep- Vulnerability Scanner
        Version 2.0
        
        
        Made by team RootX

        
        Features:
        - Port scanning
        - Service detection
        - OS fingerprinting
        - SQLi detection
        - XSS detection
        
        Use responsibly and ethically.
        """
        messagebox.showinfo("About CipherSweep", about)

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=BOTH, expand=True)

        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=X, pady=(0, 10))

        ttk.Label(header_frame, text="CipherSweep",
                  style='Title.TLabel').pack(side=LEFT)
        ttk.Label(header_frame, text="Vulnerability Scanner",
                  style='Subtitle.TLabel').pack(side=LEFT, padx=10)

        # Target
        target_frame = ttk.LabelFrame(
            main_frame, text="Scan Target", padding=10)
        target_frame.pack(fill=X, pady=5)

        ttk.Label(target_frame, text="Target (IP/URL):").grid(row=0,
                                                              column=0, sticky=W, padx=5)
        self.target_entry = ttk.Entry(target_frame, width=40)
        self.target_entry.grid(row=0, column=1, sticky=EW, padx=5)

        # Port range
        port_frame = ttk.Frame(target_frame)
        port_frame.grid(row=1, column=0, columnspan=2, sticky=W, pady=5)

        ttk.Label(port_frame, text="Port Range:").pack(side=LEFT, padx=5)
        self.start_port = ttk.Entry(port_frame, width=8)
        self.start_port.pack(side=LEFT, padx=5)
        self.start_port.insert(0, "1")
        ttk.Label(port_frame, text="to").pack(side=LEFT)
        self.end_port = ttk.Entry(port_frame, width=8)
        self.end_port.pack(side=LEFT, padx=5)
        self.end_port.insert(0, "1024")

        # Scan options
        options_frame = ttk.LabelFrame(
            main_frame, text="Scan Options", padding=10)
        options_frame.pack(fill=X, pady=10)

        opt_row1 = ttk.Frame(options_frame)
        opt_row1.pack(fill=X, pady=5)

        self.port_scan_var = IntVar(value=1)
        ttk.Checkbutton(opt_row1, text="Port Scan",
                        variable=self.port_scan_var).pack(side=LEFT, padx=10)

        self.service_detect_var = IntVar(value=1)
        ttk.Checkbutton(opt_row1, text="Service Detection",
                        variable=self.service_detect_var).pack(side=LEFT, padx=10)

        self.os_detect_var = IntVar()
        ttk.Checkbutton(opt_row1, text="OS Detection",
                        variable=self.os_detect_var).pack(side=LEFT, padx=10)

        opt_row2 = ttk.Frame(options_frame)
        opt_row2.pack(fill=X, pady=5)

        self.web_vuln_var = IntVar()
        ttk.Checkbutton(opt_row2, text="Web Vulnerabilities (SQLi)",
                        variable=self.web_vuln_var).pack(side=LEFT, padx=10)

        self.xss_var = IntVar()
        ttk.Checkbutton(opt_row2, text="XSS Detection",
                        variable=self.xss_var).pack(side=LEFT, padx=10)

        self.brute_force_var = IntVar()
        ttk.Checkbutton(opt_row2, text="Common Directories",
                        variable=self.brute_force_var).pack(side=LEFT, padx=10)

        # Button
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)

        self.scan_button = ttk.Button(
            button_frame, text="Start Scan", command=self.start_scan, style='Accent.TButton')
        self.scan_button.pack(side=LEFT, padx=5)

        self.stop_button = ttk.Button(
            button_frame, text="Stop Scan", command=self.stop_scan, state=DISABLED)
        self.stop_button.pack(side=LEFT, padx=5)

        self.save_button = ttk.Button(
            button_frame, text="Save Report", command=self.save_report)
        self.save_button.pack(side=LEFT, padx=5)

        self.clear_button = ttk.Button(
            button_frame, text="Clear Results", command=self.clear_results)
        self.save_button.pack(side=LEFT, padx=5)

        # Results
        results_frame = ttk.LabelFrame(
            main_frame, text="Scan Results", padding=10)
        results_frame.pack(fill=BOTH, expand=True)

        self.results_text = scrolledtext.ScrolledText(
            results_frame, wrap=WORD, font=('Consolas', 10))
        self.results_text.pack(fill=BOTH, expand=True)

        # Status bar
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=X, pady=(5, 0))

        self.status_var = StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(
            status_frame, textvariable=self.status_var, relief=SUNKEN, style='Status.TLabel')
        status_bar.pack(side=LEFT, fill=X, expand=True)

        self.progress = ttk.Progressbar(
            status_frame, orient=HORIZONTAL, mode='determinate')
        self.progress.pack(side=LEFT, fill=X, expand=True)

        # Configure grid weights
        target_frame.columnconfigure(1, weight=1)

    def reset_scan(self):
        self.stop_scan()
        self.target_entry.delete(0, END)
        self.start_port.delete(0, END)
        self.start_port.insert(0, "1")
        self.end_port.delete(0, END)
        self.end_port.insert(0, "1024")
        self.clear_results()

    def clear_results(self):
        self.results_text.delete(1.0, END)
        self.progress['value'] = 0
        self.status_var.set("Ready")

    def start_scan(self):
        if self.scan_active:
            return

        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return

        try:
            start_port = int(self.start_port.get())
            end_port = int(self.end_port.get())
            if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
                messagebox.showerror(
                    "Error", "Ports must be between 1 and 65535")
                return
            if start_port > end_port:
                messagebox.showerror("Error", "Invalid port range")
                return
        except ValueError:
            messagebox.showerror("Error", "Invalid port range")
            return

        self.results_text.delete(1.0, END)
        self.scan_active = True
        self.stop_event.clear()
        self.scan_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)
        self.save_button.config(state=DISABLED)

        scan_thread = threading.Thread(target=self.run_scan, args=(
            target, start_port, end_port), daemon=True)
        scan_thread.start()

    def stop_scan(self):
        self.stop_event.set()
        self.update_status("Scan stopping...")
        self.scan_button.config(state=NORMAL)
        self.stop_button.config(state=DISABLED)

    def run_scan(self, target, start_port, end_port):
        try:
            self.log_message(
                f"[*] Starting scan of {target} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            self.log_message("[*] Configuration:")
            self.log_message(f"    Port Range: {start_port}-{end_port}")
            self.log_message(f"    Threads: {self.max_threads}")
            self.log_message(f"    Timeout: {self.timeout}s")

            if not self.is_host_up(target):
                self.log_message(
                    "[-] Target appears to be offline or blocking requests")
                self.update_status("Target offline")
                return

            if self.port_scan_var.get() and not self.stop_event.is_set():
                self.scan_ports(target, start_port, end_port)

            if self.service_detect_var.get() and not self.stop_event.is_set():
                self.service_detection(target)

            if self.os_detect_var.get() and not self.stop_event.is_set():
                self.os_detection(target)

            if (self.web_vuln_var.get() or self.xss_var.get()) and not self.stop_event.is_set():
                self.check_web_application(target)

            if not self.stop_event.is_set():
                self.log_message("\n[*] Scan completed successfully")
                self.update_status("Scan completed")
                self.save_button.config(state=NORMAL)

        except Exception as e:
            self.log_message(f"[-] Critical error during scan: {str(e)}")
            self.update_status("Scan failed")
        finally:
            self.scan_active = False
            self.scan_button.config(state=NORMAL)
            self.stop_button.config(state=DISABLED)
            self.progress['value'] = 0

    def is_host_up(self, target):
        self.update_status("Checking host availability...")
        host = target.split('//')[-1].split('/')[0].split(':')[0]

        try:
            # Try a TCP connection to port 80 or 443 first
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((host, 80 if not host.startswith('https:') else 443))
                return True
        except:
            try:
                # Fall back to ICMP ping if TCP fails
                param = '-n' if os.name == 'nt' else '-c'
                command = ['ping', param, '1', host]
                return subprocess.call(command, stdout=subprocess.DEVNULL) == 0
            except:
                return False

    def scan_ports(self, target, start_port, end_port):
        if self.stop_event.is_set():
            return

        total_ports = end_port - start_port + 1
        self.log_message(
            f"\n[+] Scanning {target} (ports {start_port}-{end_port})")
        open_ports = []
        self.progress['maximum'] = total_ports
        self.progress['value'] = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self.port_scanner, target, port): port
                for port in range(start_port, end_port + 1)
            }

            for future in concurrent.futures.as_completed(futures):
                if self.stop_event.is_set():
                    break
                port, service, status = future.result()
                self.progress['value'] += 1
                self.root.update()

                if status == "open":
                    open_ports.append((port, service))
                    self.log_message(f"[+] Port {port}: {service} (open)")

        if not self.stop_event.is_set():
            self.log_message(
                f"\n[+] Found {len(open_ports)} open ports out of {total_ports} scanned")
            if open_ports:
                self.log_message("[+] Open ports:")
                for port, service in sorted(open_ports):
                    self.log_message(f"    {port}/tcp - {service}")

    def port_scanner(self, target, port):
        host = target.split('//')[-1].split('/')[0].split(':')[0]

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))

                if result == 0:
                    try:
                        service = socket.getservbyport(port, 'tcp')
                    except:
                        # Try to get service from common ports list
                        service = self.get_common_service(port)
                    return port, service, "open"
                return port, None, "closed"
        except Exception as e:
            return port, None, f"error: {str(e)}"
        finally:
            time.sleep(0.05)  # Small delay to avoid flooding

    def get_common_service(self, port):
        common_ports = {
            20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
            25: "smtp", 53: "dns", 80: "http", 110: "pop3",
            143: "imap", 443: "https", 465: "smtps", 993: "imaps",
            995: "pop3s", 3306: "mysql", 3389: "rdp", 5900: "vnc"
        }
        return common_ports.get(port, "unknown")

    def service_detection(self, target):
        if self.stop_event.is_set():
            return

        self.log_message(f"\n[+] Performing service detection on {target}")
        try:
            scanner = nmap.PortScanner()
            scanner.scan(
                target, arguments=f'-T4 -sV --version-light --host-timeout {self.timeout*60}s')

            if not scanner.all_hosts():
                self.log_message("[-] Host not found or not responding")
                return

            host = scanner[target]
            for proto in host.all_protocols():
                if self.stop_event.is_set():
                    return

                self.log_message(f"\n[+] Protocol: {proto.upper()}")
                ports = sorted(host[proto].keys())

                for port in ports:
                    service = host[proto][port]
                    product = service.get('product', '')
                    version = service.get('version', '')
                    extrainfo = service.get('extrainfo', '')

                    info_parts = []
                    if product:
                        info_parts.append(product)
                    if version:
                        info_parts.append(version)
                    if extrainfo:
                        info_parts.append(extrainfo)

                    service_info = " ".join(
                        info_parts) if info_parts else "No additional info"
                    self.log_message(
                        f"    Port {port}: {service['name']} - {service_info}")
        except nmap.PortScannerError as e:
            self.log_message(f"[-] Nmap error: {str(e)}")
        except Exception as e:
            self.log_message(f"[-] Service detection failed: {str(e)}")

    def os_detection(self, target):
        if self.stop_event.is_set():
            return

        self.log_message(f"\n[+] Performing OS detection on {target}")
        try:
            nm = nmap.PortScanner()
            nm.scan(
                hosts=target, arguments=f'-O --osscan-limit --host-timeout {self.timeout*30}s')

            if not nm.all_hosts():
                self.log_message("[-] Host not found or not responding")
                return

            host = nm[target]
            if 'osmatch' not in host:
                self.log_message("[-] No OS matches found")
                return

            self.log_message("\n[+] Possible OS Matches:")
            for osmatch in host['osmatch']:
                if self.stop_event.is_set():
                    return

                self.log_message(
                    f"\n    Name: {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)")
                for osclass in osmatch['osclass']:
                    self.log_message(f"    Type: {osclass['type']}")
                    self.log_message(f"    Vendor: {osclass['vendor']}")
                    self.log_message(f"    OS Family: {osclass['osfamily']}")
                    self.log_message(f"    Version: {osclass['osgen']}")
                    if 'cpe' in osclass:
                        self.log_message(f"    CPE: {osclass['cpe']}")
        except nmap.PortScannerError as e:
            self.log_message(f"[-] Nmap error: {str(e)}")
        except Exception as e:
            self.log_message(f"[-] OS detection failed: {str(e)}")

    def check_web_application(self, target):
        """Check for both SQLi and XSS vulnerabilities"""
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target

        # Normalize target URL
        target = target.rstrip('/')

        if self.web_vuln_var.get() and not self.stop_event.is_set():
            self.check_sql_injection(target)

        if self.xss_var.get() and not self.stop_event.is_set():
            self.check_xss_vulnerabilities(target)

    def check_sql_injection(self, target):
        if self.stop_event.is_set():
            return

        self.log_message(
            f"\n[+] Testing {target} for SQL Injection vulnerabilities")
        vulnerable = False

        test_urls = [
            f"{target}/product?id=1",
            f"{target}/category?id=1",
            f"{target}/user?id=1",
            f"{target}/search?q=test"
        ]

        for test_url in test_urls:
            if self.stop_event.is_set():
                return

            try:
                # First check if the parameter is reflected
                response = requests.get(test_url, timeout=self.timeout)

                for payload in self.payloads:
                    if self.stop_event.is_set():
                        return

                    try:
                        # Test with parameter tampering
                        malicious_url = test_url.replace("=1", f"={payload}")
                        response = requests.get(
                            malicious_url, timeout=self.timeout)

                        # More sophisticated detection
                        if (any(err in response.text.lower() for err in ['error', 'syntax', 'sql', 'database']) or
                            "mysql" in response.text.lower() or
                            "sqlite" in response.text.lower() or
                            "postgresql" in response.text.lower() or
                            "odbc" in response.text.lower() or
                                len(response.text) > len(requests.get(test_url).text) * 1.5):

                            self.log_message(
                                f"[!] Possible SQLi vulnerability at: {malicious_url}")
                            vulnerable = True
                            break
                    except requests.RequestException as e:
                        self.log_message(
                            f"[-] Error testing SQLi payload {payload}: {str(e)}")
                        continue

                    time.sleep(0.1)  # Rate limiting

            except requests.RequestException as e:
                self.log_message(f"[-] Error testing URL {test_url}: {str(e)}")
                continue

        if not vulnerable and not self.stop_event.is_set():
            self.log_message(
                "[-] No obvious SQL injection vulnerabilities detected")

    def check_xss_vulnerabilities(self, target):
        if self.stop_event.is_set():
            return

        self.log_message(f"\n[+] Testing {target} for XSS vulnerabilities")
        found_xss = False

        test_urls = [
            f"{target}/search?q=test",
            f"{target}/contact?name=test",
            f"{target}/profile?user=test"
        ]

        for test_url in test_urls:
            if self.stop_event.is_set():
                return

            for payload in self.xss_payloads:
                if self.stop_event.is_set():
                    return

                try:
                    malicious_url = test_url.replace("=test", f"={payload}")
                    response = requests.get(
                        malicious_url, timeout=self.timeout)

                    # Check if payload is reflected AND not encoded
                    if (payload in response.text and
                            not ("&lt;" in response.text and "&gt;" in response.text)):

                        self.log_message(
                            f"[!] Possible XSS vulnerability at: {malicious_url}")
                        found_xss = True
                except requests.RequestException as e:
                    self.log_message(
                        f"[-] Error testing XSS payload {payload}: {str(e)}")
                    continue

                time.sleep(0.1)  # Rate limiting

        if not found_xss and not self.stop_event.is_set():
            self.log_message("[-] No reflected XSS vulnerabilities detected")

    def save_report(self):
        content = self.results_text.get("1.0", END).strip()
        if not content:
            messagebox.showwarning("Warning", "No scan results to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Files", "*.html"),
                       ("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Save Scan Report"
        )

        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("""<!DOCTYPE html>
<html>
<head>
    <title>CipherSweep Report</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .header { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .scan-info { margin-bottom: 20px; }
        .vulnerability { background-color: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin: 10px 0; }
        .critical { background-color: #f8d7da; border-left-color: #dc3545; }
        .warning { background-color: #fff3cd; border-left-color: #ffc107; }
        .info { background-color: #d1ecf1; border-left-color: #17a2b8; }
        pre { background-color: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>CipherSweep Pro Vulnerability Report</h1>
    <div class="header">
        <div class="scan-info">
            <strong>Scan Date:</strong> {date}<br>
            <strong>Target:</strong> {target}<br>
        </div>
    </div>
    <pre>
{content}
    </pre>
</body>
</html>""".format(
                        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        target=self.target_entry.get(),
                        content=content
                    ))

                messagebox.showinfo(
                    "Success", f"Report saved to:\n{file_path}")
                if messagebox.askyesno("Open Report", "Would you like to open the report now?"):
                    webbrowser.open(file_path)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file:\n{e}")

    def log_message(self, message):
        """Thread-safe logging to the results text area"""
        def safe_write():
            self.results_text.insert(END, message + "\n")
            self.results_text.see(END)
            self.results_text.update_idletasks()

        self.root.after(0, safe_write)

    def update_status(self, message):
        """Thread-safe status updates"""
        def safe_update():
            self.status_var.set(message)
            self.root.update_idletasks()

        self.root.after(0, safe_update)


if __name__ == "__main__":
    root = Tk()
    app = CipherSweepGUI(root)
    root.mainloop()
