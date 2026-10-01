"""
STAGE 2 OF 3 — DETECTION
========================

This module turns FACTS (collected in context.py) into CONCLUSIONS.

Every detector follows the same contract:

    def detect_something(ctx):     takes a context dict
        ...
        return findings            returns a LIST of finding dictionaries

Three rules that make the contract work:

  1. A detector NEVER prints anything.
     Printing is report.py's job. A detector that prints cannot be used in
     JSON output mode, and cannot be tested (a test would have to capture
     stdout instead of just checking a return value).

  2. A detector NEVER touches the packets.
     It only reads the Context. That is why it can be tested without a pcap
     file at all - you build a Context by hand, set one attribute, and call
     the detector. See ROADMAP.md, step 5.

  3. A detector NEVER knows about the other detectors.
     They are completely independent. Adding one cannot break another.

To add a new detector you do exactly three things:
     a) collect whatever raw data it needs in context.py -> feed()
     b) write the detect_*() function here
     c) add its name to the DETECTORS list at the bottom of this file
main.py does not change. report.py does not change.
"""


import ipaddress


# ======================================================================
# THRESHOLDS
#
# All tuning values live together at the top of the file rather than
# being buried as magic numbers inside the functions. When there are six
# detectors, this is the one place you look to adjust sensitivity.
# ======================================================================

# Minimum number of unique destination ports before we call it a scan.
SYN_SCAN_THRESHOLD = 20
FIN_SCAN_THRESHOLD = 5
UDP_SCAN_THRESHOLD = 5
NULL_SCAN_THRESHOLD = 0 #Packet should not be empty , if empty one comes most likely we are being scanned
XMAS_SCAN_THRESHOLD = 0 #Same logic ,packet should not be this way
MITM_ATTACK_THRESHOLD = 1
DNS_TUNNEL_LABEL_THRESHOLD = 30
DNS_TUNNEL_NAMES_THRESHOLD = 50



def _scan_finding(ip, scan, finding_type, severity, description):
    """Build one scan finding from a scan record (see context.make_context).

    All five scan detectors report the same facts - who, which ports, when,
    how fast, in what order - and differ only in type, severity and wording.
    Keeping the shape in one place is what lets report.py print any of them
    without knowing which detector it came from.
    """
    ports = scan['ports']
    duration = scan['last_ts'] - scan['first_ts']

    # dict order = order the scanner first touched each port.
    order = list(ports)

    return {
        'type': finding_type,
        'severity': severity,
        'source': ip,
        'description': description,

        # Sorted, because report.py folds consecutive ports into ranges.
        'ports': sorted(ports),

        'start': scan['first_ts'],
        'end': scan['last_ts'],
        'first_frame': scan['first_frame'],
        'last_frame': scan['last_frame'],
        'duration': duration,
        # None rather than a division by zero when every probe landed in
        # the same timestamp - "infinitely fast" is not a useful number.
        'rate': len(ports) / duration if duration else None,

        # A conclusion, so it lives here and not in context.py. nmap
        # shuffles ports by default; a strictly ascending walk points at
        # "nmap -r", a hand-written script, or a naive tool.
        'sequential': order == sorted(order),

        # The full story, one entry per port, in the order it happened.
        # report.py shows it only under --full; JSON always carries it.
        'timeline': [{'port': port, 'time': ts, 'frame': frame}
                     for port, (ts, frame) in ports.items()],
    }


def detect_syn_scan(ctx, threshold=SYN_SCAN_THRESHOLD):
    """Detect SYN port scanning.

    A host that sends TCP SYN packets to many different ports is almost
    certainly enumerating which services are open, rather than doing normal
    work - a normal client connects to one or two ports on a server.

    The threshold is a function argument with a default rather than a hard
    constant, so a test can call detect_syn_scan(ctx, threshold=5) with a
    small fixture, and so a --threshold CLI flag can be wired in later
    without touching this code.
    """
    found_threats = []

    # ctx['ip_ports'] was filled in by feed(). Shape: src_ip -> scan record
    for ip, scan in ctx['ip_ports'].items():
        if len(scan['ports']) > threshold:
            found_threats.append(_scan_finding(
                ip, scan, 'PORT_SCAN', 'HIGH',
                f'{ip} scanned {len(scan["ports"])} unique ports'))

    return found_threats


def detect_fin_scan(ctx, threshold=FIN_SCAN_THRESHOLD):
    """Detect FIN (stealth) port scanning.

    A bare TCP FIN packet (flags == 'F', no SYN/ACK) sent to a port that
    never saw a handshake is not a normal teardown - it's the classic
    RFC793-based stealth scan technique described in nmap's docs. A host
    sending bare FIN to many different ports is enumerating open/closed
    state the same way a SYN scanner does, just via non-response instead
    of SYN-ACK.
    """
    found_threats = []

    for ip, scan in ctx['fin_scan_ports'].items():
        if len(scan['ports']) > threshold:
            found_threats.append(_scan_finding(
                ip, scan, 'FIN_SCAN', 'HIGH',
                f'{ip} sent bare FIN to {len(scan["ports"])} unique ports'))

    return found_threats


def detect_udp_scan(ctx, threshold=UDP_SCAN_THRESHOLD):
    found_threats = []

    for ip, scan in ctx['udp_scan_ports'].items():
        if len(scan['ports']) > threshold:
            found_threats.append(_scan_finding(
                ip, scan, 'UDP_SCAN', 'HIGH',
                f'{ip} sent UDP to {len(scan["ports"])} unique ports'))

    return found_threats


def detect_null_scan(ctx, threshold=NULL_SCAN_THRESHOLD):
    found_threats = []

    for ip, scan in ctx['null_scan_ports'].items():
        if len(scan['ports']) > threshold:
            found_threats.append(_scan_finding(
                ip, scan, 'NULL_SCAN', 'MEDIUM',
                f'{ip} sent NULL PACKET to {len(scan["ports"])} unique ports'))

    return found_threats


def detect_xmas_scan(ctx, threshold=XMAS_SCAN_THRESHOLD):
    found_threats = []

    for ip, scan in ctx['xmas_scan_ports'].items():
        if len(scan['ports']) > threshold:
            found_threats.append(_scan_finding(
                ip, scan, 'XMAS_SCAN', 'MEDIUM',
                f'{ip} sent FIN, PUSH, URG PACKETS to {len(scan["ports"])} unique ports'))

    return found_threats


def detect_mitm_attack(ctx, threshold=MITM_ATTACK_THRESHOLD):

    found_threats = []

    # ctx['arp_table']: ip -> {mac: (ts, frame)}, in order of first claim
    for ip, macs in ctx['arp_table'].items():

        if len(macs) > threshold:
            mac_list = ', '.join(sorted(macs))

            # The attack starts when the SECOND MAC shows up, not the
            # first - the first one is usually the legitimate owner.
            claims = sorted(macs.items(), key=lambda item: item[1][0])
            takeover_ts, takeover_frame = claims[1][1]

            found_threats.append({
                'type': 'MITM_ATTACK',
                'severity': 'HIGH',
                'source': ip,
                'description': f'{ip} claimed by {len(macs)} MACs: {mac_list}',
                'start': takeover_ts,
                'first_frame': takeover_frame,
                'timeline': [{'mac': mac, 'time': ts, 'frame': frame}
                             for mac, (ts, frame) in claims],
            })

    return found_threats


def detect_dns_tunnel(ctx,
                      label_threshold=DNS_TUNNEL_LABEL_THRESHOLD,
                      names_threshold=DNS_TUNNEL_NAMES_THRESHOLD):
    """Find domains that are being used to carry data rather than to name hosts.

    Two conditions, deliberately ANDed rather than ORed. Either one alone
    fires on ordinary traffic: DKIM and CDN hostnames are long, and a big
    CDN legitimately serves hundreds of distinct subdomains. Together they
    almost never occur outside a tunnel.
    """

    found_threats = []

    for domain, data in ctx['dns_domains'].items():

        if data['max_label'] > label_threshold and len(data['names']) > names_threshold:

            # The domain is what is guilty, but an analyst starts from the
            # machine, so the host goes in 'source' and the domain into the
            # description.
            host_list = ', '.join(sorted(data['sources']))

            found_threats.append({
                'type': 'DNS_TUNNEL',
                'severity': 'HIGH',
                'source': host_list,
                'description': (f'{domain}: {len(data["names"])} unique names, '
                                f'longest label {data["max_label"]} chars, '
                                f'{data["txt"]} TXT queries'),
                'start': data['first_ts'],
                'end': data['last_ts'],
                'first_frame': data['first_frame'],
                'last_frame': data['last_frame'],
                'duration': data['last_ts'] - data['first_ts'],
            })

    return found_threats


def detect_modbus_unauthorized_master(ctx):
    """Report every IP that sent Modbus requests without being allowed to.

    In an industrial network the set of machines that may give orders to
    field devices is short and known: the SCADA server, an engineering
    workstation or two. Anything else talking TO port 502 is an incident,
    however polite its requests are - reading one register is how an
    attacker learns the process before changing it.

    The tool cannot know that set; the analyst passes it with
    --allow-master. Without it this detector stays silent rather than
    guessing - every master would otherwise look unauthorized.

    No threshold: one request is enough. An unknown master is not
    "suspicious above N", it is wrong at 1.
    """
    allowed = ctx['config']['modbus_masters']
    if allowed is None:
        return []

    found_threats = []

    for ip, master in ctx['modbus']['masters'].items():
        address = ipaddress.ip_address(ip)

        # 'address in network' is False, not an error, when the two are
        # different IP versions - an IPv6 master against an IPv4 allowlist
        # simply does not match, and is reported.
        if any(address in network for network in allowed):
            continue

        targets = ', '.join(sorted(master['slaves']))
        writes = len(master['writes'])

        description = (f'{ip} is not an allowed master but sent '
                       f'{master["requests"]} Modbus requests to {targets}')
        if writes:
            # The part that turns "someone is looking" into "someone
            # changed something" - said in the description, not only
            # buried in a number.
            description += f', including {writes} writes'

        found_threats.append({
            'type': 'MODBUS_UNAUTHORIZED_MASTER',
            'severity': 'HIGH',
            'source': ip,
            'description': description,
            'targets': sorted(master['slaves']),
            'requests': master['requests'],
            'writes': writes,
            'start': master['first_ts'],
            'end': master['last_ts'],
            'first_frame': master['first_frame'],
            'last_frame': master['last_frame'],
            'duration': master['last_ts'] - master['first_ts'],
            # What it did, in the order it first did it - one entry per
            # function code, like one entry per port in a scan.
            'timeline': [{'fc': fc, 'time': ts, 'frame': frame}
                         for fc, (ts, frame) in master['function_codes'].items()],
        })

    return found_threats


# ======================================================================
# THE REGISTRY
#
# main.py loops over this list and runs whatever is in it. That is the
# reason main.py never needs to be edited when a detector is added: it
# does not know any detector by name, it only knows this list.
# ======================================================================

DETECTORS = [
    detect_syn_scan,
    detect_fin_scan,
    detect_udp_scan,
    detect_null_scan,
    detect_xmas_scan,
    detect_mitm_attack,
    detect_dns_tunnel,
    detect_modbus_unauthorized_master,
]
