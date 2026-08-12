"""
STAGE 2 OF 3 — DETECTION
========================

This module turns FACTS (collected in context.py) into CONCLUSIONS.

Every detector follows the same contract:

    def detect_something(ctx):     takes a Context
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
     a) collect whatever raw data it needs in context.py -> Context.feed()
     b) write the detect_*() function here
     c) add its name to the DETECTORS list at the bottom of this file
main.py does not change. report.py does not change.
"""


# ======================================================================
# THRESHOLDS
#
# All tuning values live together at the top of the file rather than
# being buried as magic numbers inside the functions. When there are six
# detectors, this is the one place you look to adjust sensitivity.
# ======================================================================

# Minimum number of unique destination ports before we call it a scan.
SYN_SCAN_THRESHOLD = 20


def detect_syn_scan(ctx, threshold=SYN_SCAN_THRESHOLD):
    """Detect SYN port scanning.

    A host that sends TCP SYN packets to many different ports is almost
    certainly enumerating which services are open, rather than doing normal
    work - a normal client connects to one or two ports on a server.

    This is the second loop ("PASS 2") from the old threat_checking(). The
    data collection half of that function now lives in context.py; what is
    left here is only the decision-making.

    The threshold is a function argument with a default rather than a hard
    constant, so a test can call detect_syn_scan(ctx, threshold=5) with a
    small fixture, and so a --threshold CLI flag can be wired in later
    without touching this code.
    """

    # List to store detected threats (returned at the end)
    found_threats = []

    # ctx.ip_ports was filled in by Context.feed(). Shape: src_ip -> set(ports)
    for ip, ports in ctx.ip_ports.items():
        if len(ports) > threshold:

            # NOTE: the two print() calls that used to be here are gone.
            # The detector now only records what it found; report.py decides
            # how (and whether) to display it.
            found_threats.append({
                'type': 'PORT_SCAN',
                'severity': 'HIGH',
                'source': ip,
                'description': f'{ip} scanned {len(ports)} unique ports',

                # 'ports' is the one field that did not exist before. It has
                # to be here now: the old code printed sorted(ports) directly
                # from inside this loop, and since printing has moved to
                # report.py, the port list has to travel with the finding.
                'ports': sorted(ports),
            })

    # NOTE: the old "if not found_threats: print(...)" check is also gone.
    # That message is about the whole report, not about this one detector,
    # so it belongs in report.print_findings().

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
]
