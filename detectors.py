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

from modbus import (
    WRITE_FCS, COIL_ON, COIL_OFF,
    DIAG_RESTART_COMMUNICATIONS, DIAG_FORCE_LISTEN_ONLY, DIAG_CLEAR_COUNTERS,
)


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

# Distinct Modbus function codes one master may use before it counts as a
# sweep. A SCADA poller uses 2-4 (10.1.1.234 in modbus_test.pcap: 3), a full
# HMI up to about 8 (1, 2, 3, 4, 5, 6, 15, 16), an engineering workstation a
# few more on top (8, 17, 43, a vendor code). A sweep uses dozens to all 128.
MODBUS_FC_SWEEP_THRESHOLD = 10

# Distinct addresses one master may write to before it counts as a mass
# write. The SCADA master in modbus_test.pcap writes 5; a recipe download
# from an HMI can legitimately fill a block of 50-100 registers. One FC 15
# setting every coil (up to 1968) is far past this on its own.
MODBUS_MASS_WRITE_THRESHOLD = 100

# Exception codes on a write that mean "you got the address or the value
# wrong" - the answers someone gets while guessing. 4 (device failure) and
# 6 (busy) are the device's own trouble and say nothing about the sender.
MODBUS_GUESSING_EXCEPTIONS = {1, 2, 3}



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


def detect_modbus_fc_sweep(ctx, threshold=MODBUS_FC_SWEEP_THRESHOLD):
    """Find masters that try many different function codes.

    The same idea as a port scan, one layer up. A port scan asks "which
    services does this host run?"; a function-code sweep asks "which
    commands does this PLC accept?". The answers - Illegal Function for
    codes that do not exist, Illegal Data Value for ones that do - give
    the attacker a map of the device before anything is changed on it.

    A real master is configured once for one device and repeats the same
    few codes forever. Variety is the trace of someone who does not know
    the device yet.

    Unlike detect_modbus_unauthorized_master this needs no allowlist, so
    it also catches a sweep from an ALLOWED address - a compromised
    SCADA server is exactly where an attacker would sweep from.

    Counted per master, over all its target devices together: a legitimate
    master polling fifty devices still uses the same three codes, so
    nothing is lost, and a sweep spread across several devices is caught.

    Requests only. The responses would confirm it, but a capture taken on
    a one-way mirror port has none, and a device that stays silent is no
    reason to miss the sweep.
    """
    found_threats = []

    for ip, master in ctx['modbus']['masters'].items():
        codes = master['function_codes']      # fc -> (ts, frame), first-use order
        if len(codes) <= threshold:
            continue

        targets = ', '.join(sorted(master['slaves']))

        # Write codes inside a sweep are not just probes. On a live PLC a
        # "test" Write Single Coil switches a real coil - in modbus_test.pcap
        # frame 139 is exactly that, and the device accepted it.
        write_codes = sorted(set(codes) & WRITE_FCS)

        description = (f'{ip} tried {len(codes)} different Modbus function codes '
                       f'against {targets}')
        if write_codes:
            description += f', including write codes {", ".join(map(str, write_codes))}'

        order = list(codes)

        found_threats.append({
            'type': 'MODBUS_FC_SWEEP',
            'severity': 'HIGH',
            'source': ip,
            'description': description,
            'targets': sorted(master['slaves']),
            # Sorted, so report.py can fold it into ranges: 0-127.
            'function_codes': sorted(codes),
            'write_codes': write_codes,
            'start': master['first_ts'],
            'end': master['last_ts'],
            'first_frame': master['first_frame'],
            'last_frame': master['last_frame'],
            'duration': master['last_ts'] - master['first_ts'],
            # 0, 1, 2 ... 127 in order is a script walking the range; a
            # shuffled order is a tool trying not to look like one.
            'sequential': order == sorted(order),
            'timeline': [{'fc': fc, 'time': ts, 'frame': frame}
                         for fc, (ts, frame) in codes.items()],
        })

    return found_threats


# Each reason the dangerous-command detector can report, with its severity
# and how to say it. Severity is per reason, not per detector: forcing a
# device into listen-only mode takes it off the network, a malformed write
# that the device rejected changed nothing.
_DANGEROUS_REASONS = {
    'force_listen_only': (
        'HIGH', '{ip} sent Force Listen Only Mode {n}x to {targets} - '
                'the device stops answering anyone until restarted'),
    'restart_communications': (
        'HIGH', '{ip} sent Restart Communications {n}x to {targets}'),
    'mass_write': (
        'HIGH', '{ip} wrote to {n} different addresses on {targets}'),
    'broadcast_write': (
        'MEDIUM', '{ip} sent {n} writes to unit 0 (broadcast) via {targets} - '
                  'every device behind a gateway executes them. Some TCP '
                  'devices take unit 0 as their own address: check whether '
                  'it answered'),
    'clear_counters': (
        'MEDIUM', '{ip} cleared the diagnostic counters {n}x on {targets}'),
    'malformed_write': (
        'MEDIUM', '{ip} sent {n} malformed write requests to {targets}'),
    'invalid_coil_value': (
        'MEDIUM', '{ip} sent {n} coil writes with a value other than '
                  'ON (0xFF00) or OFF (0x0000) to {targets}'),
    'rejected_write': (
        'MEDIUM', '{targets} rejected {n} write requests from {ip}'),
}

_DANGEROUS_DIAGNOSTICS = {
    DIAG_FORCE_LISTEN_ONLY: 'force_listen_only',
    DIAG_RESTART_COMMUNICATIONS: 'restart_communications',
    DIAG_CLEAR_COUNTERS: 'clear_counters',
}


def detect_modbus_dangerous_command(ctx, mass_threshold=MODBUS_MASS_WRITE_THRESHOLD):
    """Find Modbus commands that are abnormal on ANY site.

    Not every write - a SCADA master writes setpoints all day (20 times in
    the first 40 seconds of modbus_test.pcap), and an alert on each would
    be ignored within a day. These are the writes and commands that no
    configured master sends, whatever the plant:

      force_listen_only       FC 8/4   - device goes silent: denial of service
      restart_communications  FC 8/1   - device drops its communication state
      clear_counters          FC 8/10  - diagnostic evidence wiped
      mass_write              more than mass_threshold distinct addresses
      broadcast_write         unit 0   - executed by every device behind a gateway
      malformed_write         data that does not fit the function's layout
      invalid_coil_value      FC 5 with a value other than ON/OFF
      rejected_write          device answered exception 1, 2 or 3: guessing

    Needs no allowlist and no baseline. Who is ALLOWED to write is a
    different question, answered with site knowledge, not here.

    One finding per master and reason, not per packet: three Force Listen
    Only requests are one fact about one master, with three frames.
    """
    found_threats = []
    modbus = ctx['modbus']

    # master ip -> reason -> list of events. Each event:
    #   {'slave', 'fc', 'detail', 'time', 'frame'}
    events = {}

    def note(ip, reason, slave, fc, detail, ts, frame):
        events.setdefault(ip, {}).setdefault(reason, []).append({
            'slave': slave, 'fc': fc, 'detail': detail, 'time': ts, 'frame': frame,
        })

    for ip, master in modbus['masters'].items():

        for d in master['diagnostics']:
            reason = _DANGEROUS_DIAGNOSTICS.get(d['subfunction'])
            if reason:
                note(ip, reason, d['slave'], 8, f"sub {d['subfunction']}",
                     d['time'], d['frame'])

        # (slave, unit, space, address) - coils and registers are separate
        # address spaces, so coil 100 and register 100 are two addresses.
        written = set()

        for w in master['writes']:
            if w['malformed']:
                note(ip, 'malformed_write', w['slave'], w['fc'], None, w['time'], w['frame'])
                # Nothing below can be judged without an address.
                continue

            if w['unit'] == 0:
                note(ip, 'broadcast_write', w['slave'], w['fc'], f"addr {w['address']}",
                     w['time'], w['frame'])

            if w['fc'] == 5 and w['value'] not in (COIL_ON, COIL_OFF):
                note(ip, 'invalid_coil_value', w['slave'], 5,
                     f"addr {w['address']} = 0x{w['value']:04X}", w['time'], w['frame'])

            for address in range(w['address'], w['address'] + w['quantity']):
                written.add((w['slave'], w['unit'], w['space'], address))

        if len(written) > mass_threshold:
            # The event list is every valid write; the finding's 'n' is the
            # address count, which is what crossed the threshold.
            for w in master['writes']:
                if not w['malformed']:
                    note(ip, 'mass_write', w['slave'], w['fc'],
                         f"addr {w['address']}+{w['quantity']}", w['time'], w['frame'])
            events[ip]['mass_write_addresses'] = len(written)

    for r in modbus['rejected_writes']:
        if r['code'] in MODBUS_GUESSING_EXCEPTIONS:
            note(r['master'], 'rejected_write', r['slave'], r['fc'], f"exc {r['code']}",
                 r['time'], r['frame'])

    # ---------------- events -> findings ----------------
    for ip, by_reason in events.items():
        address_count = by_reason.pop('mass_write_addresses', None)

        for reason, items in by_reason.items():
            severity, template = _DANGEROUS_REASONS[reason]
            items.sort(key=lambda e: (e['time'], e['frame']))
            targets = sorted({e['slave'] for e in items})

            n = address_count if reason == 'mass_write' else len(items)

            found_threats.append({
                'type': 'MODBUS_DANGEROUS_COMMAND',
                'severity': severity,
                'source': ip,
                'reason': reason,
                'description': template.format(ip=ip, n=n, targets=', '.join(targets)),
                'targets': targets,
                'count': n,
                'start': items[0]['time'],
                'end': items[-1]['time'],
                'first_frame': items[0]['frame'],
                'last_frame': items[-1]['frame'],
                'duration': items[-1]['time'] - items[0]['time'],
                'timeline': [{'fc': e['fc'], 'detail': e['detail'],
                              'time': e['time'], 'frame': e['frame']}
                             for e in items],
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
    detect_modbus_fc_sweep,
    detect_modbus_dangerous_command,
]
