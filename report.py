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
wide = 147

# How many ports to show per finding before truncating. A full-range scan
# produces 65535 of them - about 450 000 characters on a single line, which
# scrolls the rest of the report out of the terminal.
MAX_PORTS_SHOWN = 10

def print_stats(ctx):
    """Print the traffic statistics block.

    This is the printing half of the old stat() function, moved out unchanged.
    The only difference is where the numbers come from: what used to be the
    local variable stats[...] is now ctx['stats'][...], filled in during the
    single packet pass in context.py.
    """

    stats = ctx['stats']  # local alias, so the lines below stay readable

    

    # Printing results
    print("\n" + "="*wide)
    print("Packet Statistics")
    print("="*wide)
    print(f" Overall packets: {stats['total_packets']}")
    print(f" IPv4: {stats['ipv4']}")
    print(f" IPv6 {stats['ipv6']}")
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

    print("="*wide)

    print(f"Unique ip addresses are {stats['unique_ips']}")

    print("="*wide)

    if len(stats['unique_ports']) < 20:
        print(f"Unique ports which had been interacted in this pcap files are {stats['unique_ports']}")


    else:
        ports_to_show = sorted(stats['unique_ports'])[:10]
        print(f"Unique ports which had been interacted in this pcap files are {ports_to_show}")

    
    print("="*wide)


def print_findings(findings):
    """Print the list of findings returned by the detectors.

    Prints from the generic fields every finding shares ('type', 'severity',
    'source', 'description', 'ports') instead of hard-coded wording, so this
    function works the same for SYN_SCAN, FIN_SCAN, or any future detector
    without needing to change.

    Long port lists are truncated to MAX_PORTS_SHOWN. The full list belongs in
    the JSON export - on screen the analyst needs the fact and the scale, not
    65535 individual numbers.
    """

    for threat in findings:
        print(f"[!] {threat['type']} ({threat['severity']}) from {threat['source']}")
        print(f"    {threat['description']}")

        # .get() instead of ['ports']: this field is specific to the scan
        # detectors. An ARP spoofing finding will not have it, and ['ports']
        # would raise KeyError and kill the whole run.
        ports = threat.get('ports')

        if ports:
            shown = ', '.join(str(p) for p in ports[:MAX_PORTS_SHOWN])

            # The slice is safe on a short list - ports[:10] just returns
            # whatever is there. The subtraction is NOT: on a 3-port finding
            # it gives -7, and the line would read "(+-7 more)". Hence the
            # guard is on the count, not on the slice.
            hidden = len(ports) - MAX_PORTS_SHOWN
            if hidden > 0:
                shown += f" (+{hidden} more)"

            print(f"    Ports: {shown}")

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
