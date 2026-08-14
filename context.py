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

Now there is exactly one walk. It happens in main.py and calls Context.feed()
for every packet. Everything that any detector might need is collected during
that single pass and stored on the Context object. Detectors then read the
Context instead of reading the packets.

This file must never import detectors.py or report.py. Dependencies only flow
one way:  main.py -> context.py / detectors.py / report.py.
Importing in both directions would create a circular import and crash Python.
"""

from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS


class Context:
    """Everything observed in one capture file.

    A Context starts out empty, gets filled in packet by packet through feed(),
    and is then handed to the detectors (detectors.py) and to the report
    printer (report.py). Both of those only READ it, they never modify it.
    """

    def __init__(self):
        # ------------------------------------------------------------------
        # General traffic statistics.
        #
        # This is the exact same dictionary that used to be created at the top
        # of stat(). It has not been restructured, so the keys you already know
        # ('tcp', 'udp', 'unique_ips', ...) all still mean the same thing.
        # The only difference is that it now lives on the object as self.stats
        # instead of being a local variable that disappears when the function
        # returns.
        # ------------------------------------------------------------------
        self.stats = {
            'total_packets': 0,   # NOTE: used to be len(packets). Since feed()
                                  # sees one packet at a time, it is now counted
                                  # up by one on every call instead.
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'arp': 0,
            'dns': 0,
            'ipv4': 0,
            'ipv6': 0,            # still never incremented - see ROADMAP.md
            'other': 0,
            'unique_ips': set(),
            'unique_ports': set(),
            'packet_sizes': []
        }

        # ------------------------------------------------------------------
        # Data collected specifically for the SYN scan detector.
        #
        # This is the ip_ports dictionary that used to live inside
        # threat_checking(). Shape:   source IP -> set of destination ports
        #
        # It is kept separate from self.stats on purpose: self.stats is
        # "things we show the user", this is "raw material for a detector".
        # When you add Modbus later, its raw material gets its own attribute
        # here too (self.modbus = [] or similar) and self.stats is left alone.
        # ------------------------------------------------------------------
        self.ip_ports = {}
        self.fin_scan_ports = {}

    def feed(self, packet, index):
        """Process exactly ONE packet.

        Called once per packet by main.py. This method contains the bodies of
        both loops that used to exist separately: the loop in stat() and the
        first loop ("PASS 1") in threat_checking(). Merging them is the whole
        point of the refactor - two loops over the same data became one.

        Arguments:
            packet -- the scapy packet object
            index  -- position of this packet in the file, starting at 0.

        The 'index' argument is not used yet. It is here because detectors
        will eventually want to report WHICH packets triggered them, so an
        analyst can type "frame.number == 142" into Wireshark. See ROADMAP.md.
        """

        # ==================================================================
        # PART A - traffic statistics (this was the loop inside stat())
        # ==================================================================

        self.stats['total_packets'] += 1
        self.stats['packet_sizes'].append(len(packet))  # Adding packet size

        # Checking if packet is an IP packet
        if IP in packet:
            self.stats['ipv4'] += 1  # Adding numbers

            ip_layer = packet[IP]  # Getting packet for the further analysis

            self.stats['unique_ips'].add(ip_layer.src)
            self.stats['unique_ips'].add(ip_layer.dst)

            if TCP in packet:
                self.stats['tcp'] += 1
                self.stats['unique_ports'].add(packet[TCP].sport)
                self.stats['unique_ports'].add(packet[TCP].dport)

            elif UDP in packet:  # UDP
                self.stats['udp'] += 1
                self.stats['unique_ports'].add(packet[UDP].sport)
                self.stats['unique_ports'].add(packet[UDP].dport)

                if DNS in packet:
                    self.stats['dns'] += 1

            elif ICMP in packet:  # ICMP protocol (ping etc.)
                self.stats['icmp'] += 1

        # Checking ARP packets (outside of IP block!)
        elif ARP in packet:
            self.stats['arp'] += 1

        else:
            self.stats['other'] += 1

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
            self.ip_ports.setdefault(src_ip, set()).add(dst_port)



        if IP in packet and TCP in packet and packet[TCP].flags == 'F':
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport

            # Same setdefault-and-add pattern as the SYN branch above,
            # but into a separate dict — bare FIN needs its own bucket
            # since it means something different from a SYN.
            self.fin_scan_ports.setdefault(src_ip, set()).add(dst_port)



            
