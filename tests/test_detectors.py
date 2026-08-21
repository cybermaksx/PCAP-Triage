"""Tests for stage 2 - detection (detectors.py).

Not a single one of these reads a pcap file. That is not a shortcut, it
is the architecture being verified: a detector reads only the context,
so a context built by hand in one line is a complete, valid input.

If a test here ever needs a capture, it means a detector started
touching packets - and rule 2 of the detector contract has been broken.
"""

import pytest

from context import make_context
from detectors import (
    DETECTORS,
    FIN_SCAN_THRESHOLD,
    NULL_SCAN_THRESHOLD,
    SYN_SCAN_THRESHOLD,
    XMAS_SCAN_THRESHOLD,
    detect_fin_scan,
    detect_null_scan,
    detect_syn_scan,
    detect_xmas_scan,
)


# ======================================================================
# SYN scan
# ======================================================================

def test_syn_fires_above_threshold():
    ctx = {'ip_ports': {'10.0.0.1': set(range(50))}}

    findings = detect_syn_scan(ctx)

    assert len(findings) == 1
    assert findings[0]['source'] == '10.0.0.1'
    assert findings[0]['type'] == 'PORT_SCAN'
    assert findings[0]['severity'] == 'HIGH'


def test_syn_silent_below_threshold():
    """Just as important as the test above.

    A detector that fires on everything is exactly as useless as one
    that never fires, and only this test can tell the two apart.
    """
    ctx = {'ip_ports': {'10.0.0.1': {22, 80, 443}}}

    assert detect_syn_scan(ctx) == []


def test_syn_silent_on_empty_context():
    assert detect_syn_scan({'ip_ports': {}}) == []


@pytest.mark.parametrize("count, expected", [
    (SYN_SCAN_THRESHOLD - 1, 0),
    (SYN_SCAN_THRESHOLD, 0),      # the comparison is '>', not '>='
    (SYN_SCAN_THRESHOLD + 1, 1),
])
def test_syn_threshold_boundary(count, expected):
    """Pins the exact edge of the comparison.

    Swapping '>' for '>=' changes behaviour by one single port and
    nothing else in the suite would notice. @parametrize runs this
    function once per row and reports each as its own test.
    """
    ctx = {'ip_ports': {'10.0.0.1': set(range(count))}}

    assert len(detect_syn_scan(ctx)) == expected


def test_syn_threshold_argument_overrides_default():
    """A small fixture plus an explicit threshold must work.

    This is why the threshold is a parameter and not a hard constant -
    see the docstring on detect_syn_scan.
    """
    ctx = {'ip_ports': {'10.0.0.1': {1, 2, 3}}}

    assert detect_syn_scan(ctx) == []
    assert len(detect_syn_scan(ctx, threshold=2)) == 1


def test_syn_reports_each_source_separately():
    ctx = {'ip_ports': {
        '10.0.0.1': set(range(50)),
        '10.0.0.2': set(range(50)),
        '10.0.0.3': {80},            # below threshold, must be skipped
    }}

    findings = detect_syn_scan(ctx)

    assert len(findings) == 2
    assert {f['source'] for f in findings} == {'10.0.0.1', '10.0.0.2'}


def test_syn_ports_are_sorted_list():
    """report.py slices this field - ports[:MAX_PORTS_SHOWN].

    A set would raise TypeError there ('set' object is not
    subscriptable), and an unsorted list would make the truncated
    output non-deterministic. The contract is: a sorted list.
    """
    ctx = {'ip_ports': {'10.0.0.1': {443, 22, 8080, *range(30)}}}

    ports = detect_syn_scan(ctx)[0]['ports']

    assert isinstance(ports, list)
    assert ports == sorted(ports)


# ======================================================================
# FIN scan
# ======================================================================

def test_fin_fires_above_threshold():
    ctx = {'fin_scan_ports': {'10.0.0.1': set(range(50))}}

    findings = detect_fin_scan(ctx)

    assert len(findings) == 1
    assert findings[0]['source'] == '10.0.0.1'
    assert findings[0]['type'] == 'FIN_SCAN'


def test_fin_silent_below_threshold():
    ctx = {'fin_scan_ports': {'10.0.0.1': {22, 80}}}

    assert detect_fin_scan(ctx) == []


@pytest.mark.parametrize("count, expected", [
    (FIN_SCAN_THRESHOLD, 0),
    (FIN_SCAN_THRESHOLD + 1, 1),
])
def test_fin_threshold_boundary(count, expected):
    ctx = {'fin_scan_ports': {'10.0.0.1': set(range(count))}}

    assert len(detect_fin_scan(ctx)) == expected


def test_detectors_read_only_their_own_bucket():
    """Rule 3: detectors are independent.

    Each is handed a context containing ONLY the other one's data. If a
    detector reached across into a bucket that is not its own, this
    would raise KeyError instead of returning an empty list.
    """
    assert detect_syn_scan({'ip_ports': {}, 'fin_scan_ports': {'x': set(range(50))}}) == []
    assert detect_fin_scan({'fin_scan_ports': {}, 'ip_ports': {'x': set(range(50))}}) == []


# ======================================================================
# NULL scan
#
# Written as a worked example - the comments explain the mechanics of a
# pytest test, not just this particular assertion.
# ======================================================================

def test_null_fires_on_a_single_port():
    """A lone flagless TCP packet is enough to report a NULL scan.

    Everything pytest needs to find and run a test is in the two lines
    above this one:

      * the file is named  test_*.py  and lives under tests/
      * the function is named  test_*  and takes no arguments
      * it is a plain function - no class, no self, nothing to inherit

    pytest imports the file, calls every test_* function it finds, and
    reports one as failed if it raises. That is the whole mechanism.
    A test that raises nothing passed.

    The name matters more than it looks. When this fails months from
    now, the first thing shown is the name - so it states the claim
    ("fires on a single port"), not the machinery ("test null 1").
    """
    # ---- ARRANGE -----------------------------------------------------
    # Build the input. make_context() rather than a hand-written
    # {'null_scan_ports': ...} on purpose: it returns every bucket that
    # exists today, so a detector added next month cannot break this
    # test with a KeyError that has nothing to do with NULL scans.
    ctx = make_context()

    # Fill in exactly the fact under test and nothing else. This is the
    # payoff of rule 2 in the detector contract - detect_null_scan reads
    # the context and never touches packets, so a valid input is one
    # dictionary key, not a capture file. No pcap, no scapy, no disk.
    #
    # One port, because that is the interesting case here: the whole
    # premise of this detector is that a flagless packet is abnormal
    # enough that a single one is worth reporting.
    ctx['null_scan_ports']['10.0.0.5'] = {80}

    # ---- ACT ---------------------------------------------------------
    # Call the thing under test. Exactly one call, with no assertions
    # tangled into it, so a failure below is unambiguous.
    findings = detect_null_scan(ctx)

    # ---- ASSERT ------------------------------------------------------
    # 'assert' is a plain Python statement, not a pytest function. If
    # the expression is falsy the test fails, and pytest rewrites the
    # line so the failure message shows the actual values on both sides:
    #
    #   assert len(findings) == 1
    #   E    assert 0 == 1
    #   E     +  where 0 = len([])
    #
    # That rewriting is why bare asserts are enough here and there is no
    # assertEqual to learn.
    assert len(findings) == 1

    # Separate asserts rather than one comparison against a whole dict.
    # A single big equality tells you "the dict differs"; these tell you
    # which field is wrong, and stop at the first one.
    finding = findings[0]
    assert finding['source'] == '10.0.0.5'
    assert finding['type'] == 'NULL_SCAN'
    assert finding['severity'] == 'MEDIUM'

    # Pin the threshold semantics too. With NULL_SCAN_THRESHOLD = 0 and
    # a '>' comparison, one port fires - but that pairing is a decision,
    # not an accident, and this is where it is written down. Flip the
    # constant to 1 and this test fails, which is the point: the test
    # exists to notice the change, not to agree with whatever the code
    # currently does.
    assert NULL_SCAN_THRESHOLD == 0


# ======================================================================
# XMAS scan
# ======================================================================

def test_xmas_fires_on_a_single_port():
    """Same threshold-0 reasoning as NULL: FIN+PSH+URG is never legitimate.

    The flag matching itself lives in context.py - this test covers only
    the decision made on top of the collected ports.
    """
    ctx = make_context()
    ctx['xmas_scan_ports']['10.0.0.5'] = {80}

    findings = detect_xmas_scan(ctx)

    assert len(findings) == 1
    assert findings[0]['source'] == '10.0.0.5'
    assert findings[0]['type'] == 'XMAS_SCAN'
    assert findings[0]['severity'] == 'MEDIUM'
    assert XMAS_SCAN_THRESHOLD == 0


def test_xmas_reports_every_scanner_not_just_the_first():
    """Guards the placement of the return statement.

    A 'return' indented into the for loop exits after the first
    iteration: the detector still works, still reports a real scanner,
    and silently drops every other one. Nothing else in the suite
    notices - a one-scanner fixture passes either way.
    """
    ctx = make_context()
    ctx['xmas_scan_ports'] = {
        '10.0.0.1': {80},
        '10.0.0.2': {81},
        '10.0.0.3': {82},
    }

    findings = detect_xmas_scan(ctx)

    assert len(findings) == 3
    assert {f['source'] for f in findings} == {'10.0.0.1', '10.0.0.2', '10.0.0.3'}


# ======================================================================
# The registry
#
# main.py loops over DETECTORS and calls whatever it finds. These tests
# guard that loop against the two mistakes that break it silently.
# ======================================================================

def test_registry_holds_functions_not_calls():
    """A missing pair of parentheses is the classic slip here.

    Writing "detect_syn_scan(ctx)" in the list would store the RESULT -
    a list - and main.py would then try to call a list.
    """
    assert DETECTORS
    assert all(callable(d) for d in DETECTORS)


def test_registry_has_no_duplicates():
    assert len(set(DETECTORS)) == len(DETECTORS)


def test_every_detector_returns_a_list_on_an_empty_context():
    """main.py does findings.extend(detect(ctx)) with no guard.

    Returning None instead of [] raises TypeError there and kills the
    whole run, so every detector must survive a context with nothing in
    it. New detectors get covered by this automatically.
    """
    # Built by make_context() rather than spelled out by hand: it returns
    # exactly the buckets that exist today, so adding a detector with a
    # new bucket keeps this test valid instead of breaking it with a
    # KeyError that has nothing to do with the detector under test.
    empty = make_context()

    for detect in DETECTORS:
        assert detect(empty) == []


def test_findings_share_one_schema():
    """report.py prints these four fields for every finding it is given.

    A detector inventing its own key names would print blanks or crash
    with KeyError. 'ports' is deliberately not required - it is specific
    to the scan detectors, which is why report.py reads it with .get().
    """
    # Same reasoning as above: start from a complete empty context, then
    # fill only the two buckets this test cares about.
    ctx = make_context()
    ctx['ip_ports']['10.0.0.1'] = set(range(50))
    ctx['fin_scan_ports']['10.0.0.2'] = set(range(50))

    findings = []
    for detect in DETECTORS:
        findings.extend(detect(ctx))

    assert len(findings) == 2
    for finding in findings:
        assert {'type', 'severity', 'source', 'description'} <= set(finding)
        assert isinstance(finding['description'], str)
