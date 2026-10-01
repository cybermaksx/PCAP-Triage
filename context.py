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

It MAY import protocol modules such as modbus.py: those only describe what a
message looks like, and import nothing from the project themselves.
"""

from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, IPv6, UDPerror, DNSQR, Padding

# Modbus/TCP knowledge lives in its own module. parse_mbap() turns a TCP
# payload into fields (or None if it is not Modbus); MODBUS_PORT tells feed()
# which packets to hand it; WRITE_FCS marks the requests worth remembering
# one by one.
from modbus import parse_mbap, MODBUS_PORT, WRITE_FCS


def make_context():
    """Create an empty context and return it.

    A context is a plain dictionary with three keys. It starts out empty,
    gets filled in packet by packet through feed(), and is then handed to
    the detectors (detectors.py) and to the report printer (report.py).
    Both of those only READ it, they never modify it.

    Shape:
        ctx['stats']           -- traffic counters, shown to the user
        ctx['ip_ports']        -- src_ip -> scan record, raw material for the SYN detector
        ctx['fin_scan_ports']  -- src_ip -> scan record, raw material for the FIN detector
        ... and the same shape for UDP, NULL and XMAS.

    A scan record (built by _record_probe) is:

        {
            'first_ts': 1727780401.123,   'first_frame': 142,
            'last_ts':  1727780402.456,   'last_frame':  9001,
            'ports': {22: (ts, frame), 443: (ts, frame), ...},
        }

    'ports' is a dict, not a set, for two reasons. A dict keeps insertion
    order, so iterating it gives the ports in the order the scanner first
    touched them. And each port carries WHEN and in WHICH frame that
    happened. len() still counts unique ports, exactly as the set did.
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
        'modbus': 0,          # well-formed Modbus/TCP messages, both directions
        'ipv4': 0,
        'ipv6': 0,
        'other': 0,
        'unique_ips': set(),
        'unique_ipv6': set(),
        'unique_ports': set(),
        'packet_sizes': [],
        # Capture time span, epoch seconds. None until the first packet -
        # an empty capture has no start, and 0 would claim it started
        # in 1970.
        'first_ts': None,
        'last_ts': None,
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
    xmas_scan_ports = {}
    arp_table = {}      # ip -> {mac: (ts, frame)}, first time each MAC claimed it
    dns_domains = {}

    # ------------------------------------------------------------------
    # Modbus/TCP. Split by ROLE, because the two sides of the protocol
    # answer different questions:
    #
    #   masters   -- who is giving orders: which devices, which function
    #                codes, which writes. Keyed by the IP that sends
    #                requests TO port 502.
    #   slaves    -- how the devices answer: how often, and with which
    #                exceptions. Keyed by the IP that answers FROM 502.
    #   malformed -- traffic on port 502 that is not valid Modbus. Kept,
    #                not dropped: scanners send garbage on purpose, and a
    #                device answering in a different protocol is a fact.
    #
    # Master record:
    #   {
    #     'requests': 407,
    #     'first_ts', 'last_ts', 'first_frame', 'last_frame',
    #     'slaves': {'10.10.5.85': {255}},       # slave ip -> unit ids used
    #     'function_codes': {6: (ts, frame), 4: (ts, frame), ...},
    #                    # first use of each FC, in order - same idea as
    #                    # 'ports' in a scan record
    #     'fc_counts': {4: 317, 3: 73, 6: 20},
    #     'writes': [{'slave', 'unit', 'fc', 'time', 'frame'}, ...],
    #   }
    #
    # Slave record:
    #   {
    #     'responses': 563,
    #     'units': {255},
    #     'exceptions': {1: 104, 3: 18},         # exception code -> count
    #   }
    # ------------------------------------------------------------------
    modbus = {
        'masters': {},
        'slaves': {},
        'malformed': [],      # [{'src', 'dst', 'time', 'frame'}, ...]
    }
    return {
        'stats': stats,
        'ip_ports': ip_ports,
        'fin_scan_ports': fin_scan_ports,
        'udp_scan_ports': udp_scan_ports,
        'null_scan_ports': null_scan_ports,
        'xmas_scan_ports': xmas_scan_ports,
        'arp_table': arp_table,
        'dns_domains': dns_domains,
        'modbus': modbus,

        # ------------------------------------------------------------------
        # The one key that is NOT a fact about the capture. It holds what
        # the analyst told the tool on the command line, filled in by
        # main.py before any packet is read. feed() never touches it.
        #
        # It travels inside the context because the detector contract is
        # "detect(ctx)" and nothing else: passing settings any other way
        # would mean main.py knowing which detector wants which setting -
        # the exact coupling the DETECTORS registry exists to avoid.
        #
        #   modbus_masters -- list of ipaddress networks allowed to act as
        #                     Modbus masters, or None when no allowlist was
        #                     given (NOT the same as "nobody is allowed")
        # ------------------------------------------------------------------
        'config': {
            'modbus_masters': None,
        },
    }


def _record_probe(ctx, key, ip, port, ts, frame):
    """Write down that 'ip' touched 'port' at time 'ts' in frame 'frame'.

    One helper for all five scan buckets - they differ only in which
    packets qualify, not in what gets remembered about them.
    """
    scan = ctx[key].setdefault(ip, {
        'first_ts': ts, 'last_ts': ts,
        'first_frame': frame, 'last_frame': frame,
        'ports': {},
    })

    # min/max rather than plain assignment: packets in a capture are
    # USUALLY in time order, but merged captures and multi-interface
    # captures can go slightly backwards.
    if ts < scan['first_ts']:
        scan['first_ts'], scan['first_frame'] = ts, frame
    if ts >= scan['last_ts']:
        scan['last_ts'], scan['last_frame'] = ts, frame

    # setdefault, not assignment: a retransmitted SYN to port 22 must not
    # move 22 to the end of the order or overwrite when it was first hit.
    scan['ports'].setdefault(port, (ts, frame))


def _tcp_payload(packet):
    """The bytes a TCP segment actually carries, without Ethernet padding.

    An Ethernet frame is at least 60 bytes, so a short segment gets zero
    bytes appended by the network card. scapy splits those off as a
    Padding layer - but bytes(packet[TCP].payload) still includes it. A
    bare ACK would then look like a 6-byte payload, and every ACK on port
    502 would be counted as malformed Modbus.
    """
    raw = bytes(packet[TCP].payload)
    if Padding in packet:
        raw = raw[:len(raw) - len(bytes(packet[Padding]))]
    return raw


def _record_modbus(ctx, packet, ts, frame):
    """Write down one TCP segment to or from port 502.

    Called only for segments that carry data - bare ACKs and handshakes
    say nothing about Modbus.
    """
    payload = _tcp_payload(packet)
    if not payload:
        return

    ip_layer = packet[IP] if IP in packet else packet[IPv6]
    src, dst = ip_layer.src, ip_layer.dst
    modbus = ctx['modbus']

    message = parse_mbap(payload)
    if message is None:
        modbus['malformed'].append({'src': src, 'dst': dst, 'time': ts, 'frame': frame})
        return

    ctx['stats']['modbus'] += 1

    # Direction decides the role - the message itself does not say.
    # dport is checked first: if BOTH ports are 502 (two devices talking
    # to each other), the sender is treated as the master.
    if packet[TCP].dport == MODBUS_PORT:
        unit = message['unit_id']

        # parse_mbap() strips the exception bit, which is right for a
        # response. A REQUEST with the bit set is not an exception, it is
        # a function code above 127 - nonsense, and worth keeping as such
        # rather than folding it into the legitimate code below it.
        fc = message['function_code']
        if message['is_exception']:
            fc |= 0x80

        master = modbus['masters'].setdefault(src, {
            'requests': 0,
            'first_ts': ts, 'last_ts': ts,
            'first_frame': frame, 'last_frame': frame,
            'slaves': {},
            'function_codes': {},
            'fc_counts': {},
            'writes': [],
        })

        master['requests'] += 1
        if ts < master['first_ts']:
            master['first_ts'], master['first_frame'] = ts, frame
        if ts >= master['last_ts']:
            master['last_ts'], master['last_frame'] = ts, frame

        master['slaves'].setdefault(dst, set()).add(unit)
        master['function_codes'].setdefault(fc, (ts, frame))
        master['fc_counts'][fc] = master['fc_counts'].get(fc, 0) + 1

        if fc in WRITE_FCS:
            master['writes'].append({
                'slave': dst, 'unit': unit, 'fc': fc,
                'time': ts, 'frame': frame,
            })

    else:
        slave = modbus['slaves'].setdefault(src, {
            'responses': 0,
            'units': set(),
            'exceptions': {},
        })

        slave['responses'] += 1
        slave['units'].add(message['unit_id'])

        if message['is_exception']:
            # None when the response was cut off before the code byte.
            code = message['exception_code']
            slave['exceptions'][code] = slave['exceptions'].get(code, 0) + 1


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

    'index' becomes the frame number (index + 1, because Wireshark counts
    from 1), so a finding can point at the exact packet: an analyst types
    "frame.number == 142" into Wireshark and lands on it.
    """

    # scapy hands the capture time over as EDecimal. float() because
    # json.dumps() cannot serialise EDecimal, and the precision lost is
    # far below the microseconds a pcap stores.
    ts = float(packet.time)
    frame = index + 1

    # ==================================================================
    # PART A - traffic statistics (this was the loop inside stat())
    # ==================================================================

    ctx['stats']['total_packets'] += 1
    ctx['stats']['packet_sizes'].append(len(packet))  # Adding packet size

    if ctx['stats']['first_ts'] is None or ts < ctx['stats']['first_ts']:
        ctx['stats']['first_ts'] = ts
    if ctx['stats']['last_ts'] is None or ts > ctx['stats']['last_ts']:
        ctx['stats']['last_ts'] = ts

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

        _record_probe(ctx, 'ip_ports', src_ip, dst_port, ts, frame)



    if IP in packet and TCP in packet and packet[TCP].flags == 'F':
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        # Same helper as the SYN branch above, but into a separate
        # bucket — bare FIN means something different from a SYN.
        _record_probe(ctx, 'fin_scan_ports', src_ip, dst_port, ts, frame)



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

        # NOTE: the time and frame are those of the ICMP REPLY, not of the
        # probe itself - the probe is indistinguishable from normal UDP.
        # On a LAN the two are a fraction of a millisecond apart.
        _record_probe(ctx, 'udp_scan_ports', scanner_ip, dst_port, ts, frame)


    if IP in packet and TCP in packet and packet[TCP].flags == 0:
         src_ip = packet[IP].src
         dst_port = packet[TCP].dport

         _record_probe(ctx, 'null_scan_ports', src_ip, dst_port, ts, frame)




    if IP in packet and TCP in packet and packet[TCP].flags == 'FPU':
         src_ip = packet[IP].src
         dst_port = packet[TCP].dport

         _record_probe(ctx, 'xmas_scan_ports', src_ip, dst_port, ts, frame)



    if ARP in packet and packet[ARP].psrc!="0.0.0.0":
        claimed_ip   = packet[ARP].psrc
        claimed_mac = packet[ARP].hwsrc

        # Same first-sighting rule as _record_probe: the moment a SECOND
        # MAC first claims an IP is the moment the spoofing started.
        ctx['arp_table'].setdefault(claimed_ip, {}).setdefault(claimed_mac, (ts, frame))



    # ------------------------------------------------------------------
    # DNS tunneling. The smuggled data rides inside the NAME being asked
    # about, not inside the addresses:  <payload>.tun.evil.com
    # The resolver is the same one normal traffic uses, so src/dst IPs
    # say nothing at all - the whole signal sits in qname.
    #
    # Three numbers give a tunnel away, and all three are collected here.
    # Measured on newtest.pcapng, which is ordinary home traffic:
    #
    #   longest label     normal 6-17 chars; a tunnel pushes against 63,
    #                     the maximum a DNS label is allowed to be
    #   unique names      normal: 1 per domain - a browser re-asks the
    #                     same name over and over. A tunnel: every query
    #                     is different, that is the point of it
    #   share of TXT      normal: 0%
    #
    # Grouped by DOMAIN, not by source IP - the first block in this file
    # that is. Source IPs are collected too, so the finding can name the
    # machine an analyst should go and look at.
    # ------------------------------------------------------------------
    if DNS in packet and IP in packet and packet[DNS].qr == 0 and DNSQR in packet:
        src_ip = packet[IP].src

        # scapy hands qname over as bytes, with the trailing root dot:
        # b'music.youtube.com.'. Without rstrip, split() below leaves an
        # empty last label and EVERY root domain comes out as 'com.'.
        #
        # errors='replace' rather than 'ignore' because a tunnel stuffs
        # arbitrary bytes into the name: 'ignore' would silently drop them
        # and shorten the string, and the length is one of the three
        # things being measured here.
        qname = packet[DNSQR].qname.decode(errors='replace').rstrip('.')

        labels = qname.split('.')

        root = '.'.join(labels[-2:])

        # mDNS is this detector's 0.0.0.0. Bonjour service names such as
        # _googlecast._tcp.local reduce to a root of '_tcp.local', so every
        # printer, TV and phone on the LAN piles into one bucket and looks
        # exactly like many unique subdomains under a single domain. Nobody
        # tunnels over mDNS - it never leaves the broadcast domain.
        if not root.endswith('.local'):

            # NOTE: only the FIRST question in the packet is read. A DNS
            # packet may carry several (qdcount was 2 in 8 packets of
            # newtest.pcapng), but all of those were mDNS and the filter
            # above has already dropped them.
            bucket = ctx['dns_domains'].setdefault(root, {
                'queries': 0,
                'max_label': 0,
                'txt': 0,
                'names': set(),
                'sources': set(),
                'first_ts': ts, 'first_frame': frame,
                'last_ts': ts, 'last_frame': frame,
            })

            if ts >= bucket['last_ts']:
                bucket['last_ts'], bucket['last_frame'] = ts, frame

            bucket['queries'] += 1

            # max() of two things, not a plain assignment: the bucket keeps
            # the record across ALL packets of this domain. Overwriting
            # would leave the length of whichever name happened to come
            # last, not the longest one.
            longest_label = max(len(label) for label in labels)
            bucket['max_label'] = max(bucket['max_label'], longest_label)

            if packet[DNSQR].qtype == 16:      # 16 = TXT
                bucket['txt'] += 1

            # NOTE: 'names' grows with the file. It is the one structure
            # here that is not constant in size, and it grows fastest on
            # exactly the case this detector is for. See ROADMAP.
            bucket['names'].add(qname)
            bucket['sources'].add(src_ip)



    # ------------------------------------------------------------------
    # Modbus/TCP. Only port 502 for now: the parser itself does not care
    # about ports, but deciding that an arbitrary TCP stream is Modbus
    # by content alone would turn every 8 bytes of noise that happen to
    # start with protocol id 0 into a "message". See ROADMAP.
    # ------------------------------------------------------------------
    if (TCP in packet and (IP in packet or IPv6 in packet)
            and MODBUS_PORT in (packet[TCP].sport, packet[TCP].dport)):
        _record_modbus(ctx, packet, ts, frame)
