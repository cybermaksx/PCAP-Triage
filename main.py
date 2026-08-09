from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS

print(f"Reading the pcap file...")

packets = rdpcap("test.pcapng")

# Analysing statistics from pcap file and returns dictionary with statistics

def stat():
    print("Getting Statistic of the packets [*]")
    stats = {
        'total_packets': len(packets),
        'tcp': 0,
        'udp': 0,
        'icmp': 0,
        'arp': 0,
        'dns': 0,
        'ipv4': 0,
        'ipv6': 0,
        'other': 0,
        'unique_ips': set(),
        'unique_ports': set(),
        'packet_sizes': []
    }
    
    for packet in packets:  # Walking through all the packets
        stats['packet_sizes'].append(len(packet))  # Adding packet size to the dict

        # Checking if packet is an IP packet
        if IP in packet:
            stats['ipv4'] += 1  # Adding numbers

            ip_layer = packet[IP]  # Getting packet for the further analysis

            stats['unique_ips'].add(ip_layer.src)
            stats['unique_ips'].add(ip_layer.dst)

            if TCP in packet:
                stats['tcp'] += 1
                stats['unique_ports'].add(packet[TCP].sport)
                stats['unique_ports'].add(packet[TCP].dport)

            elif UDP in packet:  # UDP
                stats['udp'] += 1
                stats['unique_ports'].add(packet[UDP].sport)
                stats['unique_ports'].add(packet[UDP].dport)

                if DNS in packet:
                    stats['dns'] += 1

            elif ICMP in packet:  # ICMP protocol (ping etc.)
                stats['icmp'] += 1

        # Checking ARP packets (outside of IP block!)
        elif ARP in packet:
            stats['arp'] += 1

        else:
            stats['other'] += 1
    
    # Printing results
    print("\n" + "="*100)
    print("Packet Statistics")
    print("="*100)
    print(f" Overall packets: {stats['total_packets']}")
    print(f" IPv4: {stats['ipv4']}")
    print(f" TCP: {stats['tcp']}")
    print(f" UDP: {stats['udp']}")
    print(f" ICMP: {stats['icmp']}")
    print(f" ARP: {stats['arp']}")
    print(f" DNS: {stats['dns']}")
    print(f" Other: {stats['other']}")
    print(f" Unique IP: {len(stats['unique_ips'])}")
    print(f" Uniqiue ports: {len(stats['unique_ports'])}")
    
    if stats['packet_sizes']:
        avg_size = sum(stats['packet_sizes']) / len(stats['packet_sizes'])
        print(f" Average size: {avg_size:.0f} bytes")
        print(f" Min size: {min(stats['packet_sizes'])} bytes")
        print(f" Max size: {max(stats['packet_sizes'])} bytes")
    
    print("="*100)

    #Add capability  to list and analyse unique ip adresses and ports

    print(f"Unique ip addresses are {stats['unique_ips']}")

    print("="*100)

    print(f"Unique ports which had been interacted in this pcap files are {stats['unique_ports']}")    

    print("="*100)

    
    return stats

            




def threat_checking(packets):
    # Checking pcap file on man in the middle attacks and etc
    ip_ports = []
    found_threats = []
    THRESHOLD = 20
    
    for packet in packets:
        if IP in packet and TCP in packet and packet[TCP].flags == 'S':
            src_ip = packet[IP].src
            dst_ip = packet[TCP].dport
            

        for ip,ports in ip_ports.items():
            if len(ports) > THRESHOLD:
                print(f"[!]SYN scaning is detected {ip}: {len(ports)} unique ports")
                print(f"     Ports: {sorted(ports)}")

            elif:
                print("No SYN scaning ")
            


        pass 


     return found_threats   























def report_generator():
    # coming soon
    print("Generating report... (coming soon)")
    return

def main():
    pcap_file = "test.pcapng"
    
    print(f"Reading the pcap file {pcap_file}...")
    packets = rdpcap(pcap_file)  
    print(f"Loaded {len(packets)} packets\n")
    
    
    stats = stat()
    
    
    threats = threat_checking()
    
    
    report_generator()
    
    print("\n Analysis complete!")

if __name__ == "__main__":
    main()

