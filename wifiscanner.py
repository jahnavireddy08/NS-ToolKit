import scapy.all as scapy
import socket

def wifi_scan(ip_range):
    results = []

    # Send ARP request to the specified IP range
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Process the responses
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        try:
            client_dict["hostname"] = socket.gethostbyaddr(element[1].psrc)[0]
        except socket.herror:
            client_dict["hostname"] = "Unknown"
        results.append(client_dict)

    return results

if __name__ == "__main__":
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.0/24): ")
    scan_results = wifi_scan(ip_range)
    print("IP\t\t\tMAC Address\t\t\tHostname")
    print("-" * 60)
    for client in scan_results:
        print(f"{client['ip']}\t{client['mac']}\t{client['hostname']}")
