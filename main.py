from scapy.all import rdpcap

print(f"Reading the pcap file...")

packets = rdpcap("test.pcapng")


for packet in packets:
    packet.show()









