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
formats it - that is all it does. The standard library is fair game; the
imports below are all it needs.

HOW THE LAYOUT WORKS
--------------------
Three problems the old version had, and how each is solved here:

  1. A fixed width of 147 on an 80-column terminal. Every separator wrapped
     onto a second line. Now the width is read from the terminal itself
     (_width), clamped to a sane range, and every helper respects it.

  2. Sets printed through their repr: "Unique ip addresses are {'10.0.0.1',
     ...}" was a single 276-character line in an unpredictable order, because
     set iteration order is not the sorted order. Addresses are now sorted
     properly (IPv4 before IPv6, numerically inside each family) and laid out
     in columns that fit the terminal.

  3. Port lists printed one number at a time. A scan hits consecutive ports,
     so "1, 2, 3, ..., 1024" is folded into "1-1024" - the same information in
     seven characters instead of five thousand.

FULL MODE
---------
Every limit below (MAX_PORT_GROUPS, MAX_ADDRESSES_SHOWN, MAX_ORDER_SHOWN)
exists to keep the report readable on one screen. "main.py x.pcap --full"
lifts all of them and adds a per-packet timeline to every finding. The
flag travels as a 'full' argument with a False default, so the analysis
stages never hear about it: detectors always return everything, and only
this file decides how much of it to show.
"""

import ipaddress
import shutil
import sys
import json
from datetime import datetime, timezone

# ======================================================================
# LAYOUT CONSTANTS
# ======================================================================

# How many ports to show per finding before truncating. A full-range scan
# produces 65535 of them - about 450 000 characters on a single line, which
# scrolls the rest of the report out of the terminal. The unit is RANGES,
# not ports: "1-1024" counts as one.
MAX_PORT_GROUPS = 12

# Same idea for address lists.
MAX_ADDRESSES_SHOWN = 24

# How many steps of a finding's order ("443 → 22 → 80 ...") to show.
# The order is the whole point of that line, so it cannot be folded into
# ranges the way the port list is - it is cut short instead.
MAX_ORDER_SHOWN = 15

# Width limits. Below 60 the columns stop making sense; above 100 long lines
# become hard to scan even if the terminal is wide enough to hold them.
MIN_WIDTH = 60
MAX_WIDTH = 100


def _width():
    """Usable line width, taken from the terminal and clamped.

    shutil.get_terminal_size() falls back to 80x24 when the output is not a
    terminal at all - which is exactly what happens under "main.py > out.txt"
    or inside pytest, so redirected output stays readable too.
    """
    return max(MIN_WIDTH, min(MAX_WIDTH, shutil.get_terminal_size().columns))


# ======================================================================
# COLOUR
#
# Escape codes are emitted only when stdout is an actual terminal. Piping
# the report into a file or into grep gives clean text with no codes in it -
# checking isatty() once here is what makes that automatic.
# ======================================================================

_TTY = sys.stdout.isatty()

_DIM = "2"
_BOLD = "1"
_RED = "31"
_YELLOW = "33"
_CYAN = "36"

_SEVERITY_COLOUR = {
    'HIGH': _RED,
    'MEDIUM': _YELLOW,
    'LOW': _CYAN,
}


def _c(text, code):
    """Wrap text in an ANSI colour, or return it untouched when piped."""
    if not _TTY:
        return str(text)
    return f"\033[{code}m{text}\033[0m"


# ======================================================================
# SMALL FORMATTING HELPERS
#
# Each one does a single thing and returns a string or a list of strings.
# None of them print - that keeps them trivial to try out by hand in the
# REPL:   python -i -c "import report"   then   report._fold_ports({1,2,3,9})
# ======================================================================

def _heading(title):
    """A section title with a rule under it."""
    return f"\n{_c(title.upper(), _BOLD)}\n{_c('─' * _width(), _DIM)}"


def _sort_ips(addresses):
    """Sort addresses numerically, IPv4 first, then IPv6.

    Plain sorted() is wrong here: as text, '192.168.1.9' comes after
    '192.168.1.100' because '9' > '1' character by character.

    ipaddress.ip_address fixes that, but it cannot be used as the key on its
    own either - comparing an IPv4Address with an IPv6Address raises
    "TypeError: ... are not of the same version". Hence the pair: sort by
    family first, and only compare addresses within the same family.

    Anything unparseable (a malformed address from a corrupt capture) is
    pushed to the end rather than crashing the whole report.
    """
    def key(address):
        try:
            parsed = ipaddress.ip_address(address)
            return (parsed.version, parsed)
        except ValueError:
            return (99, address)

    return sorted(addresses, key=key)


def _fold_ports(ports):
    """Collapse consecutive port numbers into ranges.

    [22, 80, 81, 82, 443]  ->  ['22', '80-82', '443']

    A port scan walks a contiguous block, so this is not a cosmetic trick: the
    full-range scan in synscan.pcapng goes from 65535 separate numbers -
    447 000 characters - down to the single string '1-65535'.
    """
    groups = []
    for port in sorted(ports):
        # Extend the current run when this port continues it, otherwise
        # start a new one. groups[-1] holds [first, last] of the run.
        if groups and port == groups[-1][1] + 1:
            groups[-1][1] = port
        else:
            groups.append([port, port])

    return [str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in groups]


def _format_ports(ports, max_groups=MAX_PORT_GROUPS):
    """Ports as one compact line, truncated if there are too many groups.

    The "+N more" counts PORTS, not ranges - "+83 more" is a useful number,
    "+7 more ranges" is not. max_groups=None means no limit (--full).
    """
    if not ports:
        return "none"

    groups = _fold_ports(ports)
    if max_groups is None or len(groups) <= max_groups:
        return ", ".join(groups)

    shown = groups[:max_groups]

    # How many individual ports the shown ranges account for, so the
    # remainder can be reported honestly.
    covered = 0
    for group in shown:
        if "-" in group:
            lo, hi = group.split("-")
            covered += int(hi) - int(lo) + 1
        else:
            covered += 1

    return f"{', '.join(shown)}  {_c(f'(+{len(ports) - covered} more)', _DIM)}"


def _columns(items, indent=4, gap=2):
    """Lay items out in as many aligned columns as the width allows.

    Returns a list of ready-to-print lines. One long address decides the
    column width for all of them, which is what makes the grid line up.
    """
    if not items:
        return [" " * indent + _c("none", _DIM)]

    cell = max(len(item) for item in items) + gap
    per_line = max(1, (_width() - indent) // cell)

    lines = []
    for start in range(0, len(items), per_line):
        row = items[start:start + per_line]
        lines.append(" " * indent + "".join(item.ljust(cell) for item in row).rstrip())
    return lines


def _ts(epoch):
    """Epoch seconds -> '2026-10-01 12:00:01.123 UTC'.

    UTC rather than local time: a report gets passed around, and "12:00"
    means a different moment on every analyst's machine. Wireshark can be
    switched to UTC too (View -> Time Display Format -> UTC Date and Time).
    """
    moment = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return moment.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + ' UTC'


def _field(label, value):
    """One labelled detail line under a finding, labels in one column."""
    return f"      {_c(f'{label:<7}', _DIM)}{value}"


def _step(entry):
    """What a timeline entry is about: a port for scans, a MAC for ARP."""
    return str(entry.get('port', entry.get('mac', '?')))


def _bar(count, total, space):
    """A proportional bar. Empty string when there is nothing to show."""
    if not total or not count:
        return ""
    filled = max(1, round(space * count / total))
    return "█" * filled


# ======================================================================
# BANNER AND PROGRESS LINES
#
# main.py used to print these itself:
#
#     print(f"Follow the white rabit")
#     print(f"Reading the pcap file ...")
#
# which quietly broke the rule this module's docstring opens with - that
# every print() in the project lives here. They have moved in, so main.py
# now says WHAT is happening and this file decides how it looks.
# ======================================================================

_TAGLINE = "follow the white rabbit"


def print_banner():
    """Draw the title box, sized to the terminal."""
    width = _width()
    inner = width - 2

    # Letter-spacing the name makes it read as a logo rather than as a
    # line of text, at no cost in dependencies or ASCII art.
    name = " ".join("PCAP-TRIAGE")

    print(file=sys.stderr)
    print(_c("╔" + "═" * inner + "╗", _CYAN), file=sys.stderr)
    print(_c("║" + " " * inner + "║", _CYAN), file=sys.stderr)
    print(_c("║", _CYAN) + _c(f"   {name}".ljust(inner), _BOLD) + _c("║", _CYAN), file=sys.stderr)
    print(_c("║", _CYAN) + _c(f"   {_TAGLINE}".ljust(inner), _DIM) + _c("║", _CYAN), file=sys.stderr)
    print(_c("║" + " " * inner + "║", _CYAN), file=sys.stderr)
    print(_c("╚" + "═" * inner + "╝", _CYAN), file=sys.stderr)
    print(file=sys.stderr)


def print_step(message):
    """A step that is starting. Dim, because it is not the result."""
    print(_c(f"  · {message}", _DIM), file=sys.stderr)


def print_ok(message):
    """A step that finished. The marker is the only coloured part."""
    print(f"  {_c('✓', _CYAN)} {message}", file=sys.stderr)


def print_error(message):
    """A failure. Goes to stderr so that "main.py x.pcap > out.txt" still
    shows the problem on screen instead of burying it in the file."""
    print(f"  {_c('✗', _RED)} {message}", file=sys.stderr)


# ======================================================================
# THE REPORT
# ======================================================================

def print_stats(ctx, source=None, full=False):
    """Print the traffic statistics block.

    'source' is optional and unused by main.py today - pass the capture
    filename to have it appear in the header. It defaults to None so that
    the existing call, report.print_stats(ctx), keeps working unchanged.

    'full' lifts the address and port limits (--full).
    """

    stats = ctx['stats']  # local alias, so the lines below stay readable
    width = _width()
    total = stats['total_packets']

    # No title block here: print_banner() has already drawn one, and two
    # headers in a row is exactly the kind of noise this rewrite removes.
    if source:
        print()
        print(_c(f"  {source}", _DIM))

    # ---------------- overview ----------------
    # Labels are padded to a fixed column so the numbers form a straight
    # right edge; ">9" right-aligns each number inside nine characters.
    print(_heading("overview"))

    rows = [
        ("Packets", total),
        ("Unique IPv4 hosts", len(stats['unique_ips'])),
        ("Unique IPv6 hosts", len(stats['unique_ipv6'])),
        ("Unique ports", len(stats['unique_ports'])),
    ]
    for label, value in rows:
        print(f"    {label:<20}{value:>9}")

    if stats['packet_sizes']:
        # Derived here rather than stored in context.py: it can always be
        # recomputed from packet_sizes, so keeping it would mean keeping two
        # things in sync for no benefit. The guard also covers the empty
        # capture, where len() would be 0 and the division would raise.
        sizes = stats['packet_sizes']
        average = sum(sizes) / len(sizes)
        print(f"    {'Packet size':<20}{min(sizes)}–{max(sizes)} bytes "
              f"{_c(f'(avg {average:.0f})', _DIM)}")

    if stats['first_ts'] is not None:
        span = stats['last_ts'] - stats['first_ts']
        print(f"    {'First packet':<20}{_ts(stats['first_ts'])}")
        print(f"    {'Last packet':<20}{_ts(stats['last_ts'])}  "
              f"{_c(f'({span:.2f} s)', _DIM)}")

    # ---------------- protocols ----------------
    print(_heading("protocols"))

    protocols = [
        ('TCP', stats['tcp']),
        ('UDP', stats['udp']),
        ('ICMP', stats['icmp']),
        ('ARP', stats['arp']),
        ('DNS', stats['dns']),
    ]

    # Widest label plus the widest count decide where the bar starts, so the
    # bars line up no matter how big the numbers get.
    count_width = max(len(str(count)) for _, count in protocols)
    bar_space = width - 4 - 6 - count_width - 10

    for name, count in sorted(protocols, key=lambda row: -row[1]):
        share = f"{100 * count / total:.1f}%" if total else "0.0%"
        print(f"    {name:<6}{count:>{count_width}}  "
              f"{_bar(count, total, bar_space):<{bar_space}} {share:>6}")

    # DNS rides on top of UDP, so the percentages above deliberately do not
    # add up to 100. The network layer does add up - that is the invariant
    # tested in tests/test_context.py.
    print()
    print(_c(f"    network layer:  IPv4 {stats['ipv4']}  ·  IPv6 {stats['ipv6']}"
             f"  ·  ARP {stats['arp']}  ·  other {stats['other']}", _DIM))

    # ---------------- addresses ----------------
    print(_heading("addresses"))

    for label, addresses in (("IPv4", stats['unique_ips']),
                             ("IPv6", stats['unique_ipv6'])):
        print(f"  {label} ({len(addresses)})")

        listed = _sort_ips(addresses)
        limit = len(listed) if full else MAX_ADDRESSES_SHOWN
        hidden = len(listed) - limit
        for line in _columns(listed[:limit]):
            print(line)
        if hidden > 0:
            print(_c(f"    (+{hidden} more)", _DIM))

    # ---------------- ports ----------------
    print(_heading(f"ports seen ({len(stats['unique_ports'])})"))
    groups = None if full else MAX_PORT_GROUPS
    print(f"    {_format_ports(stats['unique_ports'], groups)}")


def print_findings(findings, full=False):
    """Print the list of findings returned by the detectors.

    Prints from the generic fields every finding shares ('type', 'severity',
    'source', 'description', 'ports') instead of hard-coded wording, so this
    function works the same for SYN_SCAN, FIN_SCAN, UDP_SCAN, or any future
    detector without needing to change.

    The time fields ('start', 'end', 'duration', 'rate', 'timeline') are
    optional in the same way 'ports' is - each line is printed only when
    the finding carries the field it needs.

    'full' prints every port and the complete per-packet timeline (--full).
    """

    print(_heading(f"findings ({len(findings)})"))

    # This check lives here, not in the detector, because it is a statement
    # about the whole run: with several detectors registered, "nothing found"
    # can only be decided after all of them have finished.
    if not findings:
        print(f"    {_c('No threats detected', _DIM)}")
        return

    # Most severe first, so the top of the block is the part worth reading.
    # Anything with an unknown severity sorts last rather than crashing.
    order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    for threat in sorted(findings, key=lambda f: order.get(f['severity'], 9)):
        severity = threat['severity']
        colour = _SEVERITY_COLOUR.get(severity, _CYAN)

        print(f"    {_c('▸', colour)} {_c(threat['type'], _BOLD)}  "
              f"{_c(severity, colour)}  {_c('from', _DIM)} {threat['source']}")
        print(f"      {threat['description'].strip()}")

        # .get() instead of ['ports']: this field is specific to the scan
        # detectors. An ARP spoofing finding will not have it, and ['ports']
        # would raise KeyError and kill the whole run.
        ports = threat.get('ports')
        if ports:
            groups = None if full else MAX_PORT_GROUPS
            print(_field('ports', _format_ports(ports, groups)))

        # "(frame N)" is what makes a finding checkable: Wireshark filter
        # frame.number == N jumps straight to the packet.
        if threat.get('start') is not None:
            print(_field('start', f"{_ts(threat['start'])}  "
                                  f"{_c(f'(frame {threat['first_frame']})', _DIM)}"))
        if threat.get('end') is not None:
            print(_field('end', f"{_ts(threat['end'])}  "
                                f"{_c(f'(frame {threat['last_frame']})', _DIM)}"))
        if threat.get('duration') is not None:
            span = f"{threat['duration']:.3f} s"
            if threat.get('rate'):
                span += f"  ·  {threat['rate']:.0f} ports/s"
            print(_field('span', span))

        timeline = threat.get('timeline')
        if timeline:
            if full:
                _print_timeline(timeline)
            else:
                order = ' → '.join(_step(entry) for entry in timeline[:MAX_ORDER_SHOWN])
                hidden = len(timeline) - MAX_ORDER_SHOWN
                if hidden > 0:
                    order += f" {_c(f'… (+{hidden})', _DIM)}"
                if 'sequential' in threat:
                    walk = 'sequential' if threat['sequential'] else 'randomised'
                    order += f"  {_c(f'[{walk}]', _DIM)}"
                print(_field('order', order))
        print()


def _print_timeline(timeline):
    """Every step of a finding, one line each, in the order it happened.

    The "+s" column is time since the first step, which makes pauses and
    bursts visible at a glance - reading them off absolute timestamps
    means subtracting in your head.
    """
    print(_field('timeline', ''))
    # min(), not timeline[0]: the list is in FILE order, and a capture can
    # hold a packet stamped slightly earlier than the one before it (seen
    # in finscan.pcapng, frames 11 and 12). Offsets from the first line
    # would then go negative.
    start = min(entry['time'] for entry in timeline)
    frame_width = len(str(max(entry['frame'] for entry in timeline)))
    for entry in timeline:
        offset = f"+{entry['time'] - start:.3f}s"
        print(f"        {_c('frame', _DIM)} {entry['frame']:>{frame_width}}  "
              f"{_ts(entry['time'])}  {_c(f'{offset:>10}', _DIM)}  → {_step(entry)}")


def print_json(ctx, findings, source):
    stats = ctx['stats']         

    
    if stats['packet_sizes']:
        sizes = stats['packet_sizes']
        size = {
            "min": min(sizes),
            "max": max(sizes),
            "avg": round(sum(sizes) / len(sizes)),           
        }
    else:
        size = None    

    data = {
        "schema_version": 1,
        "file": source,
        "packets": stats['total_packets'],
        "stats": {
            "protocols": {
                "tcp": stats['tcp'],
                "udp": stats['udp'],
                "icmp": stats['icmp'],
                "arp": stats['arp'],
                "dns": stats['dns'],
            },
            "layers": {
                "ipv4": stats['ipv4'],
                "ipv6": stats['ipv6'],
                "arp": stats['arp'],
                "other": stats['other'],
            },
            # _sort_ips(), not sorted(): as text '192.168.1.9' sorts after
            # '192.168.1.100'. The human report already orders addresses
            # numerically, and both formats describe the same capture.
            "unique_ipv4": _sort_ips(stats['unique_ips']),
            "unique_ipv6": _sort_ips(stats['unique_ipv6']),
            "unique_ports": sorted(stats['unique_ports']),
            "packet_size": size,
            # Epoch seconds, same as every time field in the findings:
            # a consumer converts one number, not a locale-specific string.
            "first_ts": stats['first_ts'],
            "last_ts": stats['last_ts'],
        },
        "findings": findings,
    }

    print(json.dumps(data, indent=2))
