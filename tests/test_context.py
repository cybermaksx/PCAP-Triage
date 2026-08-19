"""Tests for stage 1 - fact collection (context.py).

Every number asserted here was obtained by counting the layers in the
capture with a separate scapy pass, independently of feed(). That is the
point: a test that just records whatever the code currently prints will
happily lock in a bug. These numbers say what the capture ACTUALLY
contains.
"""

import pytest


# ======================================================================
# test.pcapng - 40 packets, mixed IPv4/IPv6, no scan
# ======================================================================

def test_total_packets(test_ctx):
    assert test_ctx['stats']['total_packets'] == 40


def test_l3_counters(test_ctx):
    stats = test_ctx['stats']

    assert stats['ipv4'] == 31
    assert stats['ipv6'] == 9
    assert stats['arp'] == 0
    assert stats['other'] == 0


def test_l4_counters(test_ctx):
    """TCP must count segments carried over IPv6 as well.

    This is the regression test for the bug fixed on 19.08.2026: the L4
    block used to be nested inside "if IP in packet", so the 4 TCP
    segments riding on IPv6 were never counted and this read 25.
    """
    stats = test_ctx['stats']

    assert stats['tcp'] == 29
    assert stats['udp'] == 6
    assert stats['icmp'] == 0
    assert stats['dns'] == 6


def test_unique_addresses(test_ctx):
    stats = test_ctx['stats']

    assert len(stats['unique_ips']) == 4
    assert len(stats['unique_ipv6']) == 5

    # The two sets must not leak into each other.
    assert '192.168.1.1' in stats['unique_ips']
    assert all(':' not in ip for ip in stats['unique_ips'])
    assert all(':' in ip for ip in stats['unique_ipv6'])


# ======================================================================
# The invariant.
#
# The L3 chain has four branches and no packet can escape all four, so
# their sum is the packet count - on any capture, forever. This is the
# cheapest possible check and it is what caught "Other: 34 out of 40"
# when the if/elif chain got cut in half.
# ======================================================================

def test_l3_covers_every_packet_in_test(test_ctx):
    stats = test_ctx['stats']

    assert (stats['ipv4'] + stats['ipv6'] + stats['arp'] + stats['other']
            == stats['total_packets'])


def test_l3_covers_every_packet_in_finscan(finscan_ctx):
    stats = finscan_ctx['stats']

    assert (stats['ipv4'] + stats['ipv6'] + stats['arp'] + stats['other']
            == stats['total_packets'])


@pytest.mark.slow
def test_l3_covers_every_packet_in_synscan(synscan_ctx):
    stats = synscan_ctx['stats']

    assert (stats['ipv4'] + stats['ipv6'] + stats['arp'] + stats['other']
            == stats['total_packets'])


# ======================================================================
# finscan.pcapng - 221 packets, pure IPv4, contains a FIN scan
# ======================================================================

def test_finscan_counters(finscan_ctx):
    stats = finscan_ctx['stats']

    assert stats['total_packets'] == 221
    assert stats['ipv4'] == 219
    assert stats['ipv6'] == 0
    assert stats['arp'] == 2
    assert stats['tcp'] == 217
    assert stats['udp'] == 2
    assert stats['other'] == 0


# ======================================================================
# synscan.pcapng - 131 428 packets, full-range SYN scan
# ======================================================================

@pytest.mark.slow
def test_synscan_counters(synscan_ctx):
    stats = synscan_ctx['stats']

    assert stats['total_packets'] == 131428
    assert stats['ipv4'] == 131403
    assert stats['ipv6'] == 12
    assert stats['arp'] == 13
    assert stats['tcp'] == 131381
    assert stats['icmp'] == 1
    assert stats['other'] == 0


@pytest.mark.slow
def test_synscan_udp_counted_over_ipv6(synscan_ctx):
    """12 of the 33 UDP datagrams here travel over IPv6.

    Before the L4 fix this read 21. Same bug as test_l4_counters, on a
    different capture and a different protocol - worth pinning both,
    because a partial fix could satisfy one and not the other.
    """
    assert synscan_ctx['stats']['udp'] == 33


# ======================================================================
# Raw material handed to the detectors.
#
# feed() must fill these dicts even though nothing in stats reflects
# them. A detector cannot fire on data that was never collected.
# ======================================================================

@pytest.mark.slow
def test_syn_material_collected(synscan_ctx):
    ip_ports = synscan_ctx['ip_ports']

    assert '192.168.1.99' in ip_ports
    assert len(ip_ports['192.168.1.99']) == 65535


def test_fin_material_collected(finscan_ctx):
    fin_ports = finscan_ctx['fin_scan_ports']

    assert '192.168.1.99' in fin_ports
    assert len(fin_ports['192.168.1.99']) == 100


@pytest.mark.slow
def test_syn_and_fin_material_stay_separate(synscan_ctx):
    """A SYN packet must not end up in the FIN bucket.

    Both branches in PART B are plain 'if' statements reading the same
    packet, so a wrong flag comparison would silently populate both.
    """
    assert synscan_ctx['fin_scan_ports'] == {}
