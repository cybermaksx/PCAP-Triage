"""
STAGE 1 OF 3 — DATA COLLECTION
==============================

This module walks over the packets ONCE and writes down everything it sees.

The most important rule for this file:

    This file collects FACTS. It never decides whether something is an attack.

    FACT      -> "IP 10.0.0.66 sent SYN packets to ports 22, 80 and 443"   (goes here)
    CONCLUSION-> "10.0.0.66 is running a port scan, severity HIGH"         (goes in detectors.py)

Why the code is organised this way
----------------------------------
In the previous version of the project, main.py walked over the packet list twice:
once inside stat() and once inside threat_checking(). Every new feature (Modbus,
ARP spoofing, DNS tunneling) would have added another full walk over the packets.

Now there is exactly one walk. It happens in main.py and calls feed()
for every packet. Everything that any detector might need is collected during
that single pass and stored in the context dictionary. Detectors then read the
Context instead of reading the packets.

This file must never import detectors.py or report.py. Dependencies only flow
one way:  main.py -> context.py / detectors.py / report.py.
Importing in both directions would create a circular import and crash Python.
"""

from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, IPv6, UDPerror


def make_context():
    """Create an empty context and return it.

    A context is a plain dictionary with three keys. It starts out empty,
    gets filled in packet by packet through feed(), and is then handed to
    the detectors (detectors.py) and to the report printer (report.py).
    Both of those only READ it, they never modify it.

    Shape:
        ctx['stats']           -- traffic counters, shown to the user
        ctx['ip_ports']        -- src_ip -> set(ports), raw material for the SYN detector
        ctx['fin_scan_ports']  -- src_ip -> set(ports), raw material for the FIN detector
    """

    # ------------------------------------------------------------------
    # General traffic statistics.
    #
    # This is the exact same dictionary that used to be created at the top
    # of stat(). It has not been restructured, so the keys you already know
    # ('tcp', 'udp', 'unique_ips', ...) all still mean the same thing.
    # The only difference is that it now lives in the context dict under 'stats'
    # instead of being a local variable that disappears when the function
    # returns.
    # ------------------------------------------------------------------
    stats = {
        'total_packets': 0,   # NOTE: used to be len(packets). Since feed()
                              # sees one packet at a time, it is now counted
                              # up by one on every call instead.
        'tcp': 0,
        'udp': 0,
        'icmp': 0,
        'arp': 0,
        'dns': 0,
        'ipv4': 0,
        'ipv6': 0,            
        'other': 0,
        'unique_ips': set(),
        'unique_ipv6': set(),
        'unique_ports': set(),
        'packet_sizes': []
    }

    # ------------------------------------------------------------------
    # Data collected specifically for the SYN scan detector.
    #
    # This is the ip_ports dictionary that used to live inside
    # threat_checking(). Shape:   source IP -> set of destination ports
    #
    # It is kept separate from 'stats' on purpose: 'stats' is
    # "things we show the user", this is "raw material for a detector".
    # When you add Modbus later, its raw material gets its own key
    # here too (a 'modbus' key or similar) and 'stats' is left alone.
    # ------------------------------------------------------------------
    ip_ports = {}
    fin_scan_ports = {}
    udp_scan_ports = {}
    null_scan_ports = {}

    return {
        'stats': stats,
        'ip_ports': ip_ports,
        'fin_scan_ports': fin_scan_ports,
        'udp_scan_ports': udp_scan_ports,
        'null_scan_ports': null_scan_ports,
    }


def feed(ctx, packet, index):
    """Process exactly ONE packet.

    Called once per packet by main.py. This function contains the bodies of
    both loops that used to exist separately: the loop in stat() and the
    first loop ("PASS 1") in threat_checking(). Merging them is the whole
    point of the refactor - two loops over the same data became one.

    Arguments:
        ctx    -- the dictionary returned by make_context()
        packet -- the scapy packet object
        index  -- position of this packet in the file, starting at 0.

    The 'index' argument is not used yet. It is here because detectors
    will eventually want to report WHICH packets triggered them, so an
    analyst can type "frame.number == 142" into Wireshark. See ROADMAP.md.
    """

    # ==================================================================
    # PART A - traffic statistics (this was the loop inside stat())
    # ==================================================================

    ctx['stats']['total_packets'] += 1
    ctx['stats']['packet_sizes'].append(len(packet))  # Adding packet size

    # ------------------------------------------------------------------
    # L3 - network layer. Exactly one of these four branches runs per
    # packet, and together they must cover every packet: ipv4 + ipv6 +
    # arp + other has to add up to total_packets. That sum is the
    # cheapest sanity check in the whole file.
    # ------------------------------------------------------------------
    if IP in packet:
        ctx['stats']['ipv4'] += 1  # Adding numbers

        ip_layer = packet[IP]  # Getting packet for the further analysis

        ctx['stats']['unique_ips'].add(ip_layer.src)
        ctx['stats']['unique_ips'].add(ip_layer.dst)

    elif IPv6 in packet:
        ctx['stats']['ipv6'] += 1
        ip_layer = packet[IPv6]
        ctx['stats']['unique_ipv6'].add(ip_layer.src)
        ctx['stats']['unique_ipv6'].add(ip_layer.dst)
    # Checking ARP packets (outside of IP block!)
    elif ARP in packet:
        ctx['stats']['arp'] += 1

    else:
        ctx['stats']['other'] += 1

    # ------------------------------------------------------------------
    # L4 - transport layer. A separate top-level 'if', NOT an 'elif'
    # attached to the chain above: the two layers are independent. TCP is
    # mutually exclusive with UDP, not with ARP - and a TCP segment
    # carried over IPv6 has to be counted here exactly like one over
    # IPv4. This block used to sit nested inside the IPv4 branch, which
    # is why TCP read 25 instead of 29 on test.pcapng.
    # ------------------------------------------------------------------
    if TCP in packet:
        ctx['stats']['tcp'] += 1
        ctx['stats']['unique_ports'].add(packet[TCP].sport)
        ctx['stats']['unique_ports'].add(packet[TCP].dport)

    elif UDP in packet:  # UDP
        ctx['stats']['udp'] += 1
        ctx['stats']['unique_ports'].add(packet[UDP].sport)
        ctx['stats']['unique_ports'].add(packet[UDP].dport)

        # The only nesting in this block, and it is deliberate: DNS is
        # asked about only once the packet is known to be UDP.
        # NOTE: this misses DNS over TCP (zone transfers).
        if DNS in packet:
            ctx['stats']['dns'] += 1

    elif ICMP in packet:  # ICMP protocol (ping etc.)
        ctx['stats']['icmp'] += 1
        # NOTE: ICMP over IPv4 only. ICMPv6 is a different layer and is
        # not caught by "ICMP in packet" - see ROADMAP.md step 3.

    # ==================================================================
    # PART B - raw material for detectors
    #          (this was "PASS 1" inside threat_checking())
    #
    # Note this is a plain 'if', NOT an 'elif' attached to the block
    # above. Part A and Part B are independent: the same TCP SYN packet
    # is counted in the statistics AND recorded for the scan detector.
    # ==================================================================

    # Only process TCP SYN packets (start of new connection)
    if IP in packet and TCP in packet and packet[TCP].flags == 'S':
        src_ip = packet[IP].src          # Source IP address
        dst_port = packet[TCP].dport     # Destination port (not IP!)

        # Add port to the set belonging to this source IP.
        # setdefault creates an empty set if key doesn't exist yet, and
        # returns a REFERENCE to it, so .add() modifies the stored set
        # directly - there is no need to write it back into the dict.
        ctx['ip_ports'].setdefault(src_ip, set()).add(dst_port)



    if IP in packet and TCP in packet and packet[TCP].flags == 'F':
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        # Same setdefault-and-add pattern as the SYN branch above,
        # but into a separate dict — bare FIN needs its own bucket
        # since it means something different from a SYN.
        ctx['fin_scan_ports'].setdefault(src_ip, set()).add(dst_port)



    # UDP scan. Unlike SYN and FIN, the giveaway is not in the scanner's
    # own packets - a UDP datagram sent to an open port and one sent to a
    # closed port are byte-for-byte indistinguishable. What exposes the
    # scan is the VICTIM's reply: a closed UDP port answers with ICMP
    # type 3 code 3 (port unreachable), an open one stays silent.
    #
    # The reply carries a copy of the datagram that triggered it, which
    # scapy splits out as the IPerror/UDPerror layers. That is where the
    # scanned port comes from - there is no plain UDP layer in this
    # packet at all.
    #
    # The code 3 check is not optional: unreachable also comes in
    # host-, net- and protocol-flavours, and the UDPerror check rules out
    # unreachables provoked by something other than UDP.
    if (ICMP in packet
            and packet[ICMP].type == 3
            and packet[ICMP].code == 3
            and UDPerror in packet):

        # .dst, NOT .src. This packet travels FROM the victim TO the
        # scanner, so the scanner sits in the destination field. Reading
        # .src here - the obvious copy-paste from the two branches above -
        # would make the finding accuse the host that was scanned.
        scanner_ip = packet[IP].dst
        dst_port = packet[UDPerror].dport

        ctx['udp_scan_ports'].setdefault(scanner_ip, set()).add(dst_port)


    if IP in packet and TCP in packet and packet[TCP].flags == 0:
         src_ip = packet[IP].src
         dst_port = packet[TCP].dport

         ctx['null_scan_ports'].setdefault(src_ip, set()).add(dst_port)
        

        
        
        
        
            
