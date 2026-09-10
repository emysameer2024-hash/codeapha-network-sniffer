from scapy.all import sniff, IP, TCP, UDP
packet_count = 0
def analyze_packet(packet):
    """Display basic information about an IP packet."""
    global packet_count
    packet_count += 1

    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst
        protocol_number = packet[IP].proto

        if protocol_number == 6:
            protocol = "TCP"
        elif protocol_number == 17:
            protocol = "UDP"
        elif protocol_number == 1:
            protocol = "ICMP"
        else:
            protocol = f"Other ({protocol_number})"

        length = len(packet)

        source_port = "-"
        destination_port = "-"

        if TCP in packet:
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
        elif UDP in packet:
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        payload = packet.payload
        payload_length = len(payload)

        print("-" * 50)
        print(f"Packet #{packet_count}")
        print(f"Source IP        : {source}")
        print(f"Destination IP   : {destination}")
        print(f"Protocol         : {protocol}")
        print(f"Source Port      : {source_port}")
        print(f"Destination Port : {destination_port}")
        print(f"Packet Length    : {length} bytes")
        print(f"Payload Length   : {payload_length} bytes")
print("Starting packet sniffing...")

try:
    sniff(prn=analyze_packet, count=10)
    print("Packet sniffing completed.")

except PermissionError:
    print("Error: Permission denied. Please run the program as administrator.")

except Exception as error:
    print(f"Error while capturing packets: {error}")

finally:
    print(f"Total packets analyzed: {packet_count}")
