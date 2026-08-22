"""Tests for stage 3 - output (report.py).

Two things are worth pinning down here, and neither is about how the
report looks.

The first is that --json produces a document a machine can actually
read. "It looked fine on screen" is not the same claim: a stray print,
a set that slipped through, a float where an int was meant - all of
these still look fine and all of them break the consumer.

The second is which stream each function writes to. That is what makes
"main.py x.pcap --json | jq" work, and it is invisible from the terminal,
where stdout and stderr both land on the same screen. Only a test that
looks at the two separately can tell them apart.

capsys is a pytest built-in: it captures whatever the test printed and
hands it back as .out (stdout) and .err (stderr).
"""

import json

import pytest

from context import make_context
import report


# ======================================================================
# JSON output
# ======================================================================

def test_json_output_parses(capsys):
    """The whole point of the mode: the result is valid JSON.

    json.loads() raises on anything malformed, so no assertion about
    the exception is needed - a failure here fails the test by itself.
    """
    ctx = make_context()
    ctx['stats']['total_packets'] = 3
    ctx['stats']['unique_ips'].add('10.0.0.1')

    report.print_json(ctx, [], 'capture.pcap')

    data = json.loads(capsys.readouterr().out)

    assert data['schema_version'] == 1
    assert data['file'] == 'capture.pcap'
    assert data['packets'] == 3


def test_json_goes_to_stdout_and_nothing_else_does(capsys):
    """stdout must carry the JSON and only the JSON.

    This is the contract that makes a pipe work. A print() added to any
    of the stages later - a debug line, a warning - would land here and
    break every consumer, while looking perfectly normal on screen.
    """
    report.print_banner()
    report.print_step("collecting facts")
    report.print_ok("loaded 3 packets")
    report.print_json(make_context(), [], 'capture.pcap')

    captured = capsys.readouterr()

    json.loads(captured.out)          # stdout is parseable on its own
    assert 'P C A P' in captured.err  # the banner went the other way
    assert 'collecting facts' in captured.err
    assert 'loaded 3 packets' in captured.err


def test_json_packet_size_is_null_on_an_empty_capture(capsys):
    """An empty capture has no sizes, and the output says so.

    Reporting zeros instead would be a lie: "min": 0 asserts that
    packets were seen and the smallest was empty. null asserts nothing.
    The guard also keeps min() and the division from raising.
    """
    report.print_json(make_context(), [], 'empty.pcap')

    data = json.loads(capsys.readouterr().out)

    assert data['stats']['packet_size'] is None


def test_json_sorts_addresses_numerically(capsys):
    """Not sorted() - as text, '192.168.1.9' comes after '192.168.1.100'.

    Both orderings produce valid JSON, so the parse test above cannot
    catch this. It matters because these documents get committed and
    diffed against each other.
    """
    ctx = make_context()
    for address in ['192.168.1.100', '192.168.1.9', '192.168.1.20']:
        ctx['stats']['unique_ips'].add(address)

    report.print_json(ctx, [], 'capture.pcap')

    data = json.loads(capsys.readouterr().out)

    assert data['stats']['unique_ipv4'] == [
        '192.168.1.9', '192.168.1.20', '192.168.1.100',
    ]


def test_json_carries_findings_through_unchanged(capsys):
    """Detector output needs no translation on the way out.

    That is the payoff of rule 1 of the detector contract: because a
    detector returns data instead of printing it, the JSON mode is a
    dict literal and a dumps() call rather than a second formatter.
    """
    finding = {
        'type': 'FIN_SCAN',
        'severity': 'HIGH',
        'source': '10.0.0.1',
        'description': '10.0.0.1 sent bare FIN to 6 unique ports',
        'ports': [22, 80, 443],
    }

    report.print_json(make_context(), [finding], 'capture.pcap')

    data = json.loads(capsys.readouterr().out)

    assert data['findings'] == [finding]


# ======================================================================
# Stream separation
#
# The human report is the result in its own mode, so it belongs on
# stdout for exactly the same reason the JSON does: "main.py x.pcap >
# report.txt" should write the report and not the progress log.
# ======================================================================

@pytest.mark.parametrize("call", [
    report.print_banner,
    lambda: report.print_step("collecting facts"),
    lambda: report.print_ok("done"),
    lambda: report.print_error("no such file"),
])
def test_progress_helpers_write_to_stderr(call, capsys):
    call()

    captured = capsys.readouterr()

    assert captured.out == ""
    assert captured.err != ""


def test_human_report_writes_to_stdout(capsys):
    ctx = make_context()
    ctx['stats']['total_packets'] = 1

    report.print_stats(ctx)
    report.print_findings([])

    captured = capsys.readouterr()

    assert "OVERVIEW" in captured.out
    assert captured.err == ""
