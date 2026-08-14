"""
STAGE 3 OF 3 — OUTPUT
=====================

Every print() in the project lives in this file. Nothing else prints.

Why that matters
----------------
In the old main.py, printing was mixed into the analysis: stat() calculated
numbers AND printed them, threat_checking() detected scans AND printed them.
That works fine for one output format, but it makes three things impossible:

  * JSON output    - the numbers were printed and then thrown away, there was
                     no point where a complete result existed as data.
  * testing        - a test could not check the result without capturing stdout.
  * quiet mode     - there was no way to run the analysis without printing.

Now the pipeline is:  collect (context.py) -> decide (detectors.py) -> show (here).
The first two stages produce data. Only this stage turns data into text, so
adding a second output format means adding a function here and nothing else.

This module imports nothing from the project. It is handed finished data and
formats it - that is all it does.
"""


def print_stats(ctx):
    """Print the traffic statistics block.

    This is the printing half of the old stat() function, moved out unchanged.
    The only difference is where the numbers come from: what used to be the
    local variable stats[...] is now ctx.stats[...], filled in during the
    single packet pass in context.py.
    """

    stats = ctx.stats  # local alias, so the lines below stay readable

    # Printing results
    print("\n" + "="*200)
    print("Packet Statistics")
    print("="*200)
    print(f" Overall packets: {stats['total_packets']}")
    print(f" IPv4: {stats['ipv4']}")
    print(f" TCP: {stats['tcp']}")
    print(f" UDP: {stats['udp']}")
    print(f" ICMP: {stats['icmp']}")
    print(f" ARP: {stats['arp']}")
    print(f" DNS: {stats['dns']}")
    print(f" Other: {stats['other']}")
    print(f" Unique IP: {len(stats['unique_ips'])}")
    print(f" Unique ports: {len(stats['unique_ports'])}")

    # The average is calculated here rather than in context.py because it is a
    # DERIVED value: it can always be recomputed from packet_sizes, so storing
    # it would mean keeping two things in sync for no benefit.
    #
    # The 'if' guard matters - dividing by len() of an empty list on an empty
    # capture would raise ZeroDivisionError.
    if stats['packet_sizes']:
        avg_size = sum(stats['packet_sizes']) / len(stats['packet_sizes'])
        print(f" Average size: {avg_size:.0f} bytes")
        print(f" Min size: {min(stats['packet_sizes'])} bytes")
        print(f" Max size: {max(stats['packet_sizes'])} bytes")

    print("="*200)

    print(f"Unique ip addresses are {stats['unique_ips']}")

    print("="*200)

    print(f"Unique ports which had been interacted in this pcap files are {stats['unique_ports']}")

    print("="*200)


def print_findings(findings):
    """Print the list of findings returned by the detectors.

    These are the print() calls that used to sit inside threat_checking().
    They were moved here so that detectors return data instead of text.

    HONEST WARNING - this function is not finished.
    The wording below is still hard-coded for SYN scans ("SYN scanning
    detected from ...") because the goal of this refactor was to move code
    without changing a single character of output. As soon as a second
    detector exists, this text becomes wrong: an ARP spoofing finding would
    be announced as a SYN scan.

    The fix is to print from the fields every finding already has
    ('type', 'severity', 'source', 'description') instead of from fixed
    wording. That is step 2 in ROADMAP.md, and it is deliberately left
    for you to do.
    """

    for threat in findings:
        print(f"[!] SYN scanning detected from {threat['source']}: "
              f"{len(threat['ports'])} unique ports")
        print(f"    Ports: {threat['ports']}")

    # Print message only once if nothing was found.
    # This check lives here, not in the detector, because it is a statement
    # about the whole run: with several detectors registered, "nothing found"
    # can only be decided after all of them have finished.
    if not findings:
        print("No Threats detected")


def report_generator():
    # coming soon
    print("Generating report... (coming soon)")
    return
