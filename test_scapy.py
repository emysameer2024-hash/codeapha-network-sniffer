from scapy.all import IP

packet = IP(src="192.168.1.10", dst="8.8.8.8")

print("Source:", packet.src)
print("Destination:", packet.dst)