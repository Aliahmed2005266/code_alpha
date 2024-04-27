from scapy.all import *

def packet_handler(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        data = packet[TCP].payload

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Source Port: {src_port}")
        print(f"Destination Port: {dst_port}")
        print(f"Data: {data}")

sniff(filter="tcp", prn=packet_handler)