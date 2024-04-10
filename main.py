import tkinter as tk
from tkinter import ttk
import socket
import geocoder
import folium
import webbrowser as w
import nmap
from scapy.all import sniff
import scapy.all as scapy

class NetworkToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Toolkit")

        # Define a style for the frames
        self.style = ttk.Style()
        self.style.configure('Blue.TFrame', background='#3399ff')  # Define style with blue background
        self.style.configure('Orange.TFrame', background='#ff9900')  # Define style with orange background

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
        self.create_wifi_scanner_tab()

    def create_banner_grabber_tab(self):
        tab = ttk.Frame(self.notebook, style='Blue.TFrame')  # Apply the 'Blue.TFrame' style
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
        tab = ttk.Frame(self.notebook, style='Orange.TFrame')  # Apply the 'Orange.TFrame' style
        self.notebook.add(tab, text="Geo Location")

        url_label = ttk.Label(tab, text="Enter a URL:")
        url_label.grid(row=0, column=0, padx=5, pady=5)
        self.url_entry = ttk.Entry(tab)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5)

        btn = ttk.Button(tab, text="Get Location", command=self.get_location)
        btn.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        self.result_label = ttk.Label(tab, text="")
        self.result_label.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

    def get_location(self):
        url = self.url_entry.get()
        location = self.get_location_func(url)
        self.result_label.config(text=location)

    def get_location_func(self, url):
        try:
            ip = socket.gethostbyname(url)
            g = geocoder.ip(ip)
            myaddress = g.latlng
            myMap = folium.Map(location=myaddress, zoom_start=12)
            folium.Marker(myaddress, popup="").add_to(myMap)
            folium.CircleMarker(myaddress, radius=50, color='red', fill_color='red').add_to(myMap)
            myMap.save("map.html")
            w.open_new_tab("map.html")
            return f'Latitude: {myaddress[0]} Longitude: {myaddress[1]}\nLocation saved to map.html'
        except Exception as e:
            return str(e)

    def create_nmap_scan_tab(self):
        tab = ttk.Frame(self.notebook, style='Blue.TFrame')  # Apply the 'Blue.TFrame' style
        self.notebook.add(tab, text="Nmap Scan")

        target_label = ttk.Label(tab, text="Enter the target IP address or domain name:")
        target_label.grid(row=0, column=0, padx=5, pady=5)
        self.nmap_target_entry = ttk.Entry(tab)
        self.nmap_target_entry.grid(row=0, column=1, padx=5, pady=5)

        btn = ttk.Button(tab, text="Scan", command=self.nmap_scan)
        btn.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        self.nmap_result_text = tk.Text(tab, height=10, width=50)
        self.nmap_result_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

    def nmap_scan(self):
        target = self.nmap_target_entry.get()
        result = self.nmap_scan_func(target)
        self.nmap_result_text.delete('1.0', tk.END)  # Clear previous result
        self.nmap_result_text.insert(tk.END, result)

    def nmap_scan_func(self, target):
        try:
            nm = nmap.PortScanner()
            nm.scan(target, arguments='sS')
            scan_result = ""
            for host in nm.all_hosts():
                scan_result += f"Host: {host}\n"
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port]['name']
                        scan_result += f"Port: {port}\tState: {state}\tService: {service}\n"
            return scan_result.strip()
        except Exception as e:
            return str(e)

    def create_packet_sniffer_tab(self):
        tab = ttk.Frame(self.notebook, style='Orange.TFrame')  # Apply the 'Orange.TFrame' style
        self.notebook.add(tab, text="Packet Sniffer")

        count_label = ttk.Label(tab, text="Enter the number of packets to sniff:")
        count_label.grid(row=0, column=0, padx=5, pady=5)
        self.packet_count_entry = ttk.Entry(tab)
        self.packet_count_entry.grid(row=0, column=1, padx=5, pady=5)

        btn = ttk.Button(tab, text="Sniff", command=self.packet_sniffer)
        btn.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        self.packet_result_text = tk.Text(tab, height=10, width=50)
        self.packet_result_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

    def packet_sniffer(self):
        count = int(self.packet_count_entry.get())
        result = self.packet_sniffer_func(count)
        self.packet_result_text.delete('1.0', tk.END)  # Clear previous result
        self.packet_result_text.insert(tk.END, result)

    def packet_sniffer_func(self, count):
        packets = sniff(count=count)
        packet_data = ""
        for packet in packets:
            packet_data += str(packet) + "\n"
        return packet_data.strip()

    def create_wifi_scanner_tab(self):
        tab = ttk.Frame(self.notebook, style='Blue.TFrame')  # Apply the 'Blue.TFrame' style
        self.notebook.add(tab, text="WiFi Scanner")

        ip_range_label = ttk.Label(tab, text="Enter the IP range to scan (e.g., 192.168.1.0/24):")
        ip_range_label.grid(row=0, column=0, padx=5, pady=5)
        self.ip_range_entry = ttk.Entry(tab)
        self.ip_range_entry.grid(row=0, column=1, padx=5, pady=5)

        btn = ttk.Button(tab, text="Scan", command=self.wifi_scan)
        btn.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        self.wifi_result_text = tk.Text(tab, height=10, width=50)
        self.wifi_result_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

    def wifi_scan(self):
        ip_range = self.ip_range_entry.get()
        results = self.wifi_scan_func(ip_range)
        self.wifi_result_text.delete('1.0', tk.END)  # Clear previous result
        self.wifi_result_text.insert(tk.END, results)

    def wifi_scan_func(self, ip_range):
        results = []
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            try:
                client_dict["hostname"] = socket.gethostbyaddr(element[1].psrc)[0]
            except socket.herror:
                client_dict["hostname"] = "Unknown"
            results.append(client_dict)
        return results

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkToolkitApp(root)
    root.mainloop()
