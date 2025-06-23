# CipherSweep
CipherSweep is a Python-based GUI vulnerability scanner that enables users to identify common security issues in local or remote machines. The tool supports multithreaded port scanning, service and OS detection via Nmap, as well as basic SQL Injection and Cross-Site Scripting (XSS) detection for web targets. Built using Tkinter, the scanner is intuitive and accessible to cybersecurity beginners and professionals alike. It provides real-time feedback and enables the export of comprehensive HTML scan reports.


    • GUI: Built using Tkinter, ttk, and scrolledtext for real-time result logging
    • Multithreading: Uses threading and concurrent.futures to parallelize port scanning.
    • Scanning Modules:
    • Port Scanner: TCP socket scanning between custom port ranges
    • Service Detection: Uses nmap module with -sV arguments.
    • OS Detection: Uses nmap module with -O and –osscan-limit.
    • SQL Injection Testing: Injects SQL payloads into URL parameters and analyzes response text.
    • XSS Testing: Injects XSS payloads to detect reflected vulnerabilities.
    • Export Feature: HTML-based scan report generation using datetime and filedialog
    • Save Mechanism: Uses filedialog.asksaveasfilename() to write styled reports.
