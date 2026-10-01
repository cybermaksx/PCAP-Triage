"""
PCAP-Triage — entry point.
==========================

This file does four things and nothing else:

    1. read the command line
    2. read the pcap file
    3. run the three stages of the pipeline
    4. exit

All the actual work lives in the three modules below. That is deliberate:
main.py is the part you should almost never have to edit again.

THE PIPELINE
------------

    pcap file
        |
        v
    [ one single pass over the packets ]      <- happens here, in main()
        |
        v
    Context          "what we saw"       - facts, no interpretation
        |                                  (context.py)
        v
    [ every detector in DETECTORS ]
        |
        v
    findings         "what it means"     - conclusions, one common format
        |                                  (detectors.py)
        v
    [ printing ]                           (report.py)

WHY THIS SHAPE
--------------
Look at the detector loop below: it says "for detect in DETECTORS". main.py
does not import detect_syn_scan by name, and it has no idea what a Modbus
detector would be. It just runs whatever is registered in the list.

That is the payoff of the whole refactor. When you add Modbus support you
will edit context.py (collect the data) and detectors.py (decide + register).
This file stays exactly as it is.
"""

from scapy.all import PcapReader
from scapy.error import Scapy_Exception
import argparse
import ipaddress
import sys
# Our own modules. Note the direction of these imports: main.py imports the
# other three, and none of them import main.py or each other. Keeping arrows
# pointing one way is what prevents circular imports.
from context import make_context, feed
from detectors import DETECTORS
import report


def _networks(text):
    """'10.1.1.234,10.0.0.0/24' -> [IPv4Network('10.1.1.234/32'), IPv4Network('10.0.0.0/24')]

    A single address becomes a /32 network, so the detector only ever has
    to ask one question - "is this IP inside any of these networks?".
    strict=False accepts '10.0.0.5/24' as the /24 it belongs to instead of
    refusing it for having host bits set.

    Raising ArgumentTypeError (not ValueError) is what makes argparse print
    a clean "argument --allow-master: ..." message and exit with code 2,
    instead of a traceback.
    """
    networks = []
    for part in text.split(','):
        part = part.strip()
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            raise argparse.ArgumentTypeError(f"not an IP address or network: {part!r}")
    return networks


def parse_arg(argv=None):
    """argv=None means "read sys.argv" - tests pass a list instead."""
    parser = argparse.ArgumentParser(description = "Pcap-Triage analyse and threat hunting")
    parser.add_argument("pcap_file", help = "name of the .pcap file")
    parser.add_argument("--json", action="store_true",
                        help="print the result as JSON instead of the human report")
    parser.add_argument("--full", action="store_true",
                        help="show everything: no truncated lists, full per-packet "
                             "timeline for every finding (long - pipe it into less -R)")
    # action="extend" merges every occurrence into one flat list, so
    #   --allow-master 10.1.1.234 --allow-master 10.0.0.0/24
    #   --allow-master 10.1.1.234,10.0.0.0/24
    # mean the same thing. Without the flag the value stays None, which the
    # detector reads as "no allowlist given" - not as "nobody is allowed".
    parser.add_argument("--allow-master", type=_networks, action="extend",
                        metavar="IP[/NET][,...]",
                        help="Modbus masters that are allowed to send requests; any other "
                             "IP sending to port 502 is reported. Repeatable, accepts CIDR")
    # Same format and the same None-vs-empty rule as --allow-master.
    parser.add_argument("--allow-writer", type=_networks, action="extend",
                        metavar="IP[/NET][,...]",
                        help="Modbus masters that are allowed to WRITE (FC 5/6/15/16/22/23); "
                             "a write from any other master is reported. Also counts as "
                             "--allow-master. Repeatable, accepts CIDR")
    return parser.parse_args(argv)


def main():

    # Arguments are parsed before anything is printed, so that
    # "python main.py --help" shows only the help text. This print used to sit
    # at the top of the file, outside any function, which meant it ran on
    # import - including during --help and during test collection.
    args = parse_arg()

    report.print_banner()
    report.print_step(f"reading {args.pcap_file}")

    try:

    # ------------------------------------------------------------------
    # STAGE 1 - collect facts.
    #
    # This is the ONLY loop over the packets in the whole program. Every
    # detector, present and future, gets its raw data from this one pass.
    #
    # PcapReader streams: it parses one packet, hands it over, and forgets
    # it, instead of building a list of every packet in the file the way
    # rdpcap() did. Memory stays flat regardless of file size - on
    # synscan.pcapng the peak dropped from 696 MB to 88 MB.
    #
    # Only the collection loop belongs inside the "with". Everything below
    # reads ctx, not packets, so the file can be closed as soon as the loop
    # ends.
    #
    # enumerate() gives the position of each packet in the file. It is
    # passed to feed() so that findings can eventually point at specific
    # packet numbers - see the note in context.py.
    # ------------------------------------------------------------------
        report.print_step("collecting facts")

        ctx = make_context()

        # What the analyst knows about the site, not something the packets
        # say - see the note on 'config' in context.make_context().
        ctx['config']['modbus_masters'] = args.allow_master
        ctx['config']['modbus_writers'] = args.allow_writer

        with PcapReader(args.pcap_file) as packets:
            for index, packet in enumerate(packets):
                feed(ctx, packet, index)

        # len() does not exist on a stream, and asking for it would mean
        # reading the whole file - the thing we just stopped doing. feed()
        # has been counting packets one by one all along, so the number is
        # already in the context.
        report.print_ok(f"read {ctx['stats']['total_packets']} packets")

    # ------------------------------------------------------------------
    # STAGE 2 - turn facts into conclusions.
    #
    # extend() (not append()) because each detector returns a LIST of
    # findings - possibly empty, possibly several. append() would build a
    # list of lists instead of one flat list of findings.
    # ------------------------------------------------------------------
        report.print_step("running detectors")

        findings = []
        for detect in DETECTORS:
            findings.extend(detect(ctx))

    # ------------------------------------------------------------------
    # STAGE 3 - show the results.
    # ------------------------------------------------------------------
        if args.json:
            report.print_json(ctx, findings, args.pcap_file)
        else:
            report.print_stats(ctx, full=args.full)
            report.print_findings(findings, full=args.full)
            report.print_ok("analysis complete")

    except FileNotFoundError:
        report.print_error(f"{args.pcap_file}: no such file")
        sys.exit(1)

    except PermissionError:
        report.print_error(f"{args.pcap_file}: permission denied")
        sys.exit(1)

    except Scapy_Exception as e:
        report.print_error(f"{args.pcap_file}: not a valid capture ({e})")
        sys.exit(1)


if __name__ == "__main__":
    main()
