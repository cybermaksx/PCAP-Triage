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

from scapy.all import rdpcap
from scapy.error import Scapy_Exception
import argparse

# Our own modules. Note the direction of these imports: main.py imports the
# other three, and none of them import main.py or each other. Keeping arrows
# pointing one way is what prevents circular imports.
from context import Context
from detectors import DETECTORS
import report


def parse_arg():
    parser = argparse.ArgumentParser(description = "Pcap-Triage analyse and threat hunting")
    parser.add_argument("pcap_file", help = "name of the .pcap file")
    return parser.parse_args()


def main():

    # Arguments are parsed before anything is printed, so that
    # "python main.py --help" shows only the help text. This print used to sit
    # at the top of the file, outside any function, which meant it ran on
    # import - including during --help and during test collection.
    args = parse_arg()

    print(f"Follow the white rabit")
    print(f"Reading the pcap file ...")

    # TODO (ROADMAP.md step 1): this line still crashes with a raw scapy
    # traceback if the file is missing or is not a capture. Wrap it in
    # try/except - the exceptions to catch are FileNotFoundError,
    # PermissionError and scapy.error.Scapy_Exception.
    #
    # Also note rdpcap() loads the ENTIRE file into memory. Switching to
    # PcapReader (streaming) is ROADMAP.md step 4.

    try:
        packets = rdpcap(args.pcap_file)

        print(f"Loaded {len(packets)} packets\n")

    # ------------------------------------------------------------------
    # STAGE 1 - collect facts.
    #
    # This is the ONLY loop over the packets in the whole program. Every
    # detector, present and future, gets its raw data from this one pass.
    #
    # enumerate() gives the position of each packet in the file. It is
    # passed to feed() so that findings can eventually point at specific
    # packet numbers - see the note in context.py.
    # ------------------------------------------------------------------
        print("Getting Statistic of the packets [*]")

        ctx = Context()
        for index, packet in enumerate(packets):
            ctx.feed(packet, index)

    # ------------------------------------------------------------------
    # STAGE 2 - turn facts into conclusions.
    #
    # extend() (not append()) because each detector returns a LIST of
    # findings - possibly empty, possibly several. append() would build a
    # list of lists instead of one flat list of findings.
    # ------------------------------------------------------------------
        findings = []
        for detect in DETECTORS:
            findings.extend(detect(ctx))

    # ------------------------------------------------------------------
    # STAGE 3 - show the results.
    # ------------------------------------------------------------------
        report.print_stats(ctx)
        report.print_findings(findings)
        report.report_generator()

        print("\n Analysis complete!")




    except FileNotFoundError:
        print("File you entered doesn't exist")




    except PermissionError:
        print("You don't have permisions to use this file")


    except scapy.error.Scapy_Exception:
        print("Scappy error") #TODO i need to print scapy mistake the right way  



if __name__ == "__main__":
    main()
