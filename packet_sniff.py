from scapy.all import sniff

def packet_sniffer(count):
    packets = sniff(count=count)
    packet_data = ""
    for packet in packets:
        packet_data += str(packet) + "\n"
    return packet_data

if __name__ == "__main__":
    count = int(input("Enter the number of packets to sniff: "))
    print(packet_sniffer(count))
