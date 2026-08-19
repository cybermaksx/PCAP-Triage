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
    SYN_SCAN_THRESHOLD,
    detect_fin_scan,
    detect_syn_scan,
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
