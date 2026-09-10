import socket
import ipaddress
import queue
import threading
import csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Common service names for well-known ports (friendly names)
SERVICE_MAP = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    520: "RIP",
    548: "AFP",
    554: "RTSP",
    587: "SMTP Submission",
    631: "IPP",
    636: "LDAPS",
    873: "Rsync",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle DB",
    1723: "PPTP",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB"
}

def get_service_name(port):
    """Return a friendly service name for an open port."""
    if port in SERVICE_MAP:
        return SERVICE_MAP[port]
    try:
        service = socket.getservbyport(port, 'tcp')
        if service:
            service = service.replace('_', ' ').title()
            return service
    except (OSError, socket.error):
        pass
    return "Unknown"

class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Port Scanner - Network Security Tool")
        self.root.geometry("800x650")
        self.root.resizable(True, True)
        
        self.scanning = False
        self.total_ports = 0
        self.completed_ports = 0
        self.result_queue = queue.Queue()
        self.scan_results = []
        self.show_all_ports = tk.BooleanVar(value=True)  # Show all ports by default
        self.show_open_only = tk.BooleanVar(value=False)
        
        self._build_ui()
        self.root.after(100, self._process_queue)

    def _build_ui(self):
        # Main container
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Input frame
        input_frame = tk.LabelFrame(main_frame, text="Scan Configuration", padx=10, pady=10, font=("Arial", 10, "bold"))
        input_frame.pack(fill="x", pady=(0, 10))
        
        # Row 0: Target IP
        tk.Label(input_frame, text="Target IP Address:", font=("Arial", 10)).grid(row=0, column=0, sticky="w", pady=5)
        self.ip_entry = tk.Entry(input_frame, width=25, font=("Arial", 10))
        self.ip_entry.grid(row=0, column=1, padx=10, pady=5)
        self.ip_entry.insert(0, "127.0.0.1")
        
        # Row 1: Port Range
        tk.Label(input_frame, text="Port Range:", font=("Arial", 10)).grid(row=1, column=0, sticky="w", pady=5)
        self.range_entry = tk.Entry(input_frame, width=25, font=("Arial", 10))
        self.range_entry.grid(row=1, column=1, padx=10, pady=5)
        self.range_entry.insert(0, "1-1024")
        
        # Row 2: Buttons
        button_frame = tk.Frame(input_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.scan_btn = tk.Button(button_frame, text="🔍 Scan", command=self.start_scan, 
                                  width=12, font=("Arial", 10, "bold"), bg="#4CAF50", fg="white")
        self.scan_btn.pack(side="left", padx=5)
        
        self.export_btn = tk.Button(button_frame, text="📊 Export Results", command=self.export_results, 
                                    width=15, font=("Arial", 10, "bold"), bg="#2196F3", fg="white", 
                                    state="disabled")
        self.export_btn.pack(side="left", padx=5)
        
        self.clear_btn = tk.Button(button_frame, text="🗑 Clear", command=self.clear_results, 
                                   width=10, font=("Arial", 10, "bold"), bg="#f44336", fg="white")
        self.clear_btn.pack(side="left", padx=5)
        
        # Filter options
        filter_frame = tk.LabelFrame(input_frame, text="Display Options", font=("Arial", 9, "bold"))
        filter_frame.grid(row=0, column=2, rowspan=3, padx=20, pady=5, sticky="nsew")
        
        tk.Radiobutton(filter_frame, text="Show All Ports", variable=self.show_all_ports, 
                      value=True, command=self.apply_filter, font=("Arial", 9)).pack(anchor="w", padx=10, pady=2)
        tk.Radiobutton(filter_frame, text="Open Ports Only", variable=self.show_all_ports, 
                      value=False, command=self.apply_filter, font=("Arial", 9)).pack(anchor="w", padx=10, pady=2)
        
        # Progress frame
        progress_frame = tk.Frame(main_frame)
        progress_frame.pack(fill="x", pady=(0, 10))
        
        self.progress = ttk.Progressbar(progress_frame, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", side="left", expand=True, padx=(0, 10))
        
        self.status_label = tk.Label(progress_frame, text="Ready", width=20, font=("Arial", 10))
        self.status_label.pack(side="right")
        
        # Results table frame
        table_frame = tk.LabelFrame(main_frame, text="Scan Results (Open and Closed Ports)", padx=10, pady=10, font=("Arial", 10, "bold"))
        table_frame.pack(fill="both", expand=True)
        
        # Create Treeview with scrollbars
        columns = ("port", "status", "service", "description")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
        
        self.tree.heading("port", text="Port Number")
        self.tree.heading("status", text="Status")
        self.tree.heading("service", text="Service Detected")
        self.tree.heading("description", text="Description")
        
        self.tree.column("port", width=100, anchor="center")
        self.tree.column("status", width=120, anchor="center")
        self.tree.column("service", width=200, anchor="w")
        self.tree.column("description", width=250, anchor="w")
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=v_scrollbar.set)
        
        h_scrollbar = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(xscrollcommand=h_scrollbar.set)
        
        # Pack tree and scrollbars
        self.tree.pack(side="left", fill="both", expand=True)
        v_scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        
        # Configure tags for color coding
        self.tree.tag_configure("open", background="lightgreen", foreground="darkgreen")
        self.tree.tag_configure("closed", background="lightgray", foreground="darkgray")
        self.tree.tag_configure("filtered", background="lightyellow", foreground="orange")
        
        # Summary label
        self.summary_label = tk.Label(main_frame, text="", font=("Arial", 10, "bold"))
        self.summary_label.pack(pady=5)
        
        # Note
        note = tk.Label(main_frame, 
                       text="⚠️ Note: Scan only systems you own or have explicit permission to test.\n"
                            "🟢 Green = Open | ⚪ Gray = Closed | 🟡 Yellow = Filtered/Timeout",
                       fg="red", font=("Arial", 9, "italic"))
        note.pack(side="bottom", pady=5)

    def start_scan(self):
        if self.scanning:
            messagebox.showinfo("Scan in Progress", "A scan is already running. Please wait.")
            return

        target = self.ip_entry.get().strip()
        port_range = self.range_entry.get().strip()

        # Validate IP address
        try:
            ipaddress.ip_address(target)
        except ValueError:
            messagebox.showerror("Invalid IP", "Please enter a valid IPv4 or IPv6 address.")
            return

        # Validate port range
        try:
            if "-" in port_range:
                start_str, end_str = port_range.split("-")
                start_port = int(start_str.strip())
                end_port = int(end_str.strip())
            else:
                start_port = int(port_range.strip())
                end_port = start_port
                
            if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
                raise ValueError
            if start_port > end_port:
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Range", "Port range must be like '1-1024' or a single port like '80'.")
            return

        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.scan_results = []

        self.completed_ports = 0
        self.total_ports = end_port - start_port + 1
        self.progress["maximum"] = self.total_ports
        self.progress["value"] = 0
        self.scanning = True
        self.scan_btn.config(state="disabled")
        self.export_btn.config(state="disabled")
        self.clear_btn.config(state="disabled")
        self.status_label.config(text="Scanning...")
        self.summary_label.config(text="")

        # Run scan in background thread
        scan_thread = threading.Thread(
            target=self._run_scan,
            args=(target, start_port, end_port),
            daemon=True
        )
        scan_thread.start()

    def _run_scan(self, target, start_port, end_port):
        ports = range(start_port, end_port + 1)
        try:
            with ThreadPoolExecutor(max_workers=200) as executor:
                future_to_port = {
                    executor.submit(self._check_port, target, port): port
                    for port in ports
                }

                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    status = future.result()
                    
                    if status == "Open":
                        service = get_service_name(port)
                        description = SERVICE_MAP.get(port, "Service detected")
                    elif status == "Closed":
                        service = ""
                        description = "Port is closed"
                    else:
                        service = ""
                        description = "Filtered or timed out"
                    
                    self.result_queue.put((port, status, service, description))
        except Exception as e:
            self.result_queue.put(("ERROR", f"Scan error: {e}", "", ""))

    def _check_port(self, target, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((target, port))
                if result == 0:
                    return "Open"
                elif result in (111, 10061, 61, 10054):
                    return "Closed"
                else:
                    return "Filtered/Timeout"
        except Exception as e:
            return f"Error: {e}"

    def _process_queue(self):
        try:
            while True:
                port, status, service, description = self.result_queue.get_nowait()
                
                # Store in scan_results
                self.scan_results.append((port, status, service, description))
                
                # Update progress
                self.completed_ports += 1
                self.progress["value"] = self.completed_ports
                self.status_label.config(text=f"Scanned: {self.completed_ports}/{self.total_ports}")
                
        except queue.Empty:
            pass

        # Check if scan is complete
        if self.scanning and self.completed_ports >= self.total_ports:
            self.scanning = False
            self.scan_btn.config(state="normal")
            self.export_btn.config(state="normal")
            self.clear_btn.config(state="normal")
            self.status_label.config(text="✅ Scan Complete")
            
            # Update summary
            open_ports = [r for r in self.scan_results if r[1] == "Open"]
            closed_ports = [r for r in self.scan_results if r[1] == "Closed"]
            filtered_ports = [r for r in self.scan_results if r[1] == "Filtered/Timeout"]
            
            summary = f"🟢 Open: {len(open_ports)} | ⚪ Closed: {len(closed_ports)} | 🟡 Filtered: {len(filtered_ports)}"
            self.summary_label.config(text=summary)
            
            # Apply filter to display results
            self.apply_filter()

        self.root.after(100, self._process_queue)

    def apply_filter(self):
        """Apply display filter to show all ports or only open ports"""
        # Clear current display
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Sort results by port number
        sorted_results = sorted(self.scan_results, key=lambda x: x[0] if isinstance(x[0], int) else 0)
        
        # Display based on filter
        for port, status, service, description in sorted_results:
            if not self.show_all_ports.get() and status != "Open":
                continue  # Skip non-open ports when "Open Ports Only" is selected
            
            # Insert into tree with appropriate tag
            if status == "Open":
                item_id = self.tree.insert("", "end", values=(port, status, service, description), tags=("open",))
            elif status == "Closed":
                item_id = self.tree.insert("", "end", values=(port, status, service, description), tags=("closed",))
            else:
                item_id = self.tree.insert("", "end", values=(port, status, service, description), tags=("filtered",))

    def export_results(self):
        if not self.scan_results:
            messagebox.showwarning("No Data", "There are no scan results to export.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[
                ("CSV Files", "*.csv"),
                ("Text Files", "*.txt"),
                ("HTML Files", "*.html"),
                ("All Files", "*.*")
            ]
        )
        if not file_path:
            return

        try:
            target_ip = self.ip_entry.get().strip()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Sort results by port number
            sorted_results = sorted(self.scan_results, key=lambda x: x[0] if isinstance(x[0], int) else 0)
            
            if file_path.endswith('.html'):
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("<html><head><title>Port Scan Results</title></head><body>\n")
                    f.write(f"<h2>Port Scan Results</h2>\n")
                    f.write(f"<p><b>Target:</b> {target_ip} | <b>Date:</b> {timestamp}</p>\n")
                    f.write("<table border='1' cellpadding='5'>\n")
                    f.write("<tr><th>Port</th><th>Status</th><th>Service</th><th>Description</th></tr>\n")
                    
                    for port, status, service, description in sorted_results:
                        if status == "Open":
                            bg_color = "lightgreen"
                        elif status == "Closed":
                            bg_color = "lightgray"
                        else:
                            bg_color = "lightyellow"
                        f.write(f"<tr style='background-color: {bg_color};'><td>{port}</td><td>{status}</td><td>{service}</td><td>{description}</td></tr>\n")
                    
                    f.write("</table></body></html>")
            else:
                delimiter = "," if file_path.endswith('.csv') else "\t"
                with open(file_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f, delimiter=delimiter)
                    
                    writer.writerow(["Port Scan Results"])
                    writer.writerow(["Target IP:", target_ip])
                    writer.writerow(["Scan Date:", timestamp])
                    writer.writerow([])
                    
                    writer.writerow(["Port", "Status", "Service", "Description"])
                    
                    for port, status, service, description in sorted_results:
                        writer.writerow([port, status, service, description])
            
            messagebox.showinfo("Export Successful", f"Results saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Could not export results.\n{e}")

    def clear_results(self):
        if self.scanning:
            messagebox.showinfo("Scan in Progress", "Cannot clear results while scanning.")
            return
        
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.scan_results = []
        self.progress["value"] = 0
        self.status_label.config(text="Ready")
        self.summary_label.config(text="")
        self.export_btn.config(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()
