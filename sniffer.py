import sys
import time
from scapy.all import sniff, IP, TCP, UDP, ARP

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

def handle_packet(packet):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto
        protocol = PROTOCOLS.get(proto_num, str(proto_num))

        log_entry = f"{timestamp} - IP Packet: {src_ip} -> {dst_ip} (Protocol: {protocol})"

    elif packet.haslayer(ARP):
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst

        log_entry = f"{timestamp} - ARP Packet: {src_ip} -> {dst_ip}"

    else:
        return  

    print(log_entry) 
    with open("sniffer_log.txt", "a") as log_file:
        log_file.write(log_entry + "\n")  

def main(interface):
    print(f"\n📡 Starting Packet Sniffer on interface: {interface}")
    print("🛑 Press Ctrl+C to stop...\n")
    
    try:
        sniff(iface=interface, prn=handle_packet, store=False)
    except KeyboardInterrupt:
        print("\n✅ Sniffing stopped by user.")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python sniffer.py <interface>")
        print("💡 Tip: Use `ifconfig` or `ip a` to list available interfaces.")
        sys.exit(1)

    interface = sys.argv[1]
    main(interface)
