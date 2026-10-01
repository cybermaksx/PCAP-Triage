"""Tests for the command line (main.py).

Only argument parsing is tested here - running the whole pipeline is
what the other test files do, one stage at a time. parse_arg() takes an
argv list for exactly this reason: without it, a test would have to
overwrite sys.argv.
"""

import ipaddress

import pytest

from main import parse_arg


def _nets(*texts):
    return [ipaddress.ip_network(t) for t in texts]


def test_allow_master_defaults_to_none():
    """None, not [] - the detector treats the two differently."""
    assert parse_arg(['x.pcap']).allow_master is None


def test_allow_master_single_address_becomes_a_host_network():
    args = parse_arg(['x.pcap', '--allow-master', '10.1.1.234'])

    assert args.allow_master == _nets('10.1.1.234/32')


def test_allow_master_repeated_and_comma_separated_mean_the_same():
    repeated = parse_arg(['x.pcap', '--allow-master', '10.1.1.234',
                          '--allow-master', '10.0.0.0/24'])
    commas = parse_arg(['x.pcap', '--allow-master', '10.1.1.234, 10.0.0.0/24'])

    assert repeated.allow_master == commas.allow_master == _nets('10.1.1.234/32', '10.0.0.0/24')


def test_allow_master_network_with_host_bits_is_accepted():
    """strict=False: '10.0.0.5/24' means the /24 it sits in."""
    args = parse_arg(['x.pcap', '--allow-master', '10.0.0.5/24'])

    assert args.allow_master == _nets('10.0.0.0/24')


def test_allow_master_rejects_garbage_with_a_clean_exit(capsys):
    """argparse error, exit code 2 - not a traceback."""
    with pytest.raises(SystemExit) as exit_info:
        parse_arg(['x.pcap', '--allow-master', '10.1.1.x'])

    assert exit_info.value.code == 2
    assert "not an IP address or network: '10.1.1.x'" in capsys.readouterr().err


def test_allow_writer_parses_like_allow_master():
    args = parse_arg(['x.pcap', '--allow-writer', '10.1.1.234,10.0.0.0/24'])

    assert args.allow_writer == _nets('10.1.1.234/32', '10.0.0.0/24')
    assert args.allow_master is None          # the flags are separate


def test_allow_writer_defaults_to_none():
    assert parse_arg(['x.pcap']).allow_writer is None
