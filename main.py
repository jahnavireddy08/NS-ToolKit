import tkinter as tk
from tkinter import ttk
import socket
import geocoder
import folium
import webbrowser as w
import time
import nmap
import scapy.all as scapy

class NetworkToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Toolkit")

        self.create_widgets()

    def create_widgets(self):
        # Create a notebook widget
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create individual tabs
        self.create_banner_grabber_tab()
        self.create_geo_location_tab()
        self.create_nmap_scan_tab()
        self.create_packet_sniffer_tab()
        self.create_wifi_scan_tab()

    def create_banner_grabber_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Banner Grabber")

        target_label = ttk.Label(tab, text="Target IP address or domain name:")
        target_label.grid(row=0, column=0, padx=5, pady=5)
        self.target_entry = ttk.Entry(tab)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5)

        port_label = ttk.Label(tab, text="Port number (default is 80 for HTTP):")
        port_label.grid(row=1, column=0, padx=5, pady=5)
        self.port_entry = ttk.Entry(tab)
        self.port_entry.grid(row=1, column=1, padx=5, pady=5)

        btn = ttk.Button(tab, text="Grab Banner", command=self.banner_grabber)
        btn.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        self.result_text = tk.Text(tab, height=10, width=50)
        self.result_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

    def banner_grabber(self):
        target = self.target_entry.get()
        port = int(self.port_entry.get() or 80)
        banner = self.banner_grabber_func(target, port)
        self.result_text.delete('1.0', tk.END)  # Clear previous result
        self.result_text.insert(tk.END, banner)

    def banner_grabber_func(self, target, port=80):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((target, port))
                s.send(b"GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target).encode())
                banner = s.recv(1024)
                return banner.decode().strip()
        except Exception as e:
            return str(e)

    def create_geo_location_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Geo Location")
        # Add widgets for geo location tab here

    def create_nmap_scan_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Nmap Scan")
        # Add widgets for nmap scan tab here

    def create_packet_sniffer_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Packet Sniffer")
        # Add widgets for packet sniffer tab here

    def create_wifi_scan_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Wi-Fi Scan")
        # Add widgets for wifi scan tab here

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkToolkitApp(root)
    root.mainloop()
