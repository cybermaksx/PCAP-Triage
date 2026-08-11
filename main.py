from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS
import argparse
import os


print(f"Follow the white rabit")


def parse_arg():
    parser = argparse.ArgumentParser(description = "Pcap-Triage analyse and threat hunting")
    parser.add_argument("pcap_file", help = "name of the .pcap file")
    return parser.parse_args()

   


   # packets = rdpcap("test.pcapng")

# Analysing statistics from pcap file and returns dictionary with statistics

def stat(packets):
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
    """Detect SYN port scanning in captured packets."""

    # Dictionary to accumulate unique destination ports per source IP
    ip_ports = {}

    # List to store detected threats (returned at the end)
    found_threats = []

    # Minimum number of unique ports to consider it a scan
    THRESHOLD = 20

    # --- PASS 1: Collect data from all packets ---
    for packet in packets:
        # Only process TCP SYN packets (start of new connection)
        if IP in packet and TCP in packet and packet[TCP].flags == 'S':
            src_ip = packet[IP].src          # Source IP address
            dst_port = packet[TCP].dport     # Destination port (not IP!)

            # Add port to the set belonging to this source IP
            # setdefault creates an empty set if key doesn't exist yet
            ip_ports.setdefault(src_ip, set()).add(dst_port)

    # --- PASS 2: Analyze collected data AFTER the loop ---
    # Note: this loop is NOT inside the packet loop (check indentation!)
    for ip, ports in ip_ports.items():
        if len(ports) > THRESHOLD:
            print(f"[!] SYN scanning detected from {ip}: {len(ports)} unique ports")
            print(f"    Ports: {sorted(ports)}")

            # Append structured threat info to results list
            found_threats.append({
                'type': 'PORT_SCAN',
                'severity': 'HIGH',
                'source': ip,
                'description': f'{ip} scanned {len(ports)} unique ports'
            })

    # Print message only once if nothing was found
    if not found_threats:
        print("No SYN scanning detected")

    return found_threats

        
   

def report_generator():
    # coming soon
    print("Generating report... (coming soon)")
    return

def main():

    #pcap_file = "test.pcapng"
    
    print(f"Reading the pcap file ...")
    #packets = rdpcap(pcap_file)

    args = parse_arg() 
    packets = rdpcap(args.pcap_file)  
    print(f"Loaded {len(packets)} packets\n")
    
    
    stats = stat(packets)
    
    
    threats = threat_checking(packets)
    
    
    report_generator()
    
    print("\n Analysis complete!")

if __name__ == "__main__":
    main()

