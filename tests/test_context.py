"""Tests for stage 1 - fact collection (context.py).

Every number asserted here was obtained by counting the layers in the
capture with a separate scapy pass, independently of feed(). That is the
point: a test that just records whatever the code currently prints will
happily lock in a bug. These numbers say what the capture ACTUALLY
contains.
"""

import pytest

from context import make_context


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
    assert len(ip_ports['192.168.1.99']['ports']) == 65535


def test_fin_material_collected(finscan_ctx):
    fin_ports = finscan_ctx['fin_scan_ports']

    assert '192.168.1.99' in fin_ports
    assert len(fin_ports['192.168.1.99']['ports']) == 100


@pytest.mark.slow
def test_syn_and_fin_material_stay_separate(synscan_ctx):
    """A SYN packet must not end up in the FIN bucket.

    Both branches in PART B are plain 'if' statements reading the same
    packet, so a wrong flag comparison would silently populate both.
    """
    assert synscan_ctx['fin_scan_ports'] == {}


# ======================================================================
# Time and frame numbers.
# ======================================================================

def test_scan_record_frames_point_at_real_packets(finscan_ctx):
    """first_frame must be 1-based like Wireshark, and inside the file."""
    scan = finscan_ctx['fin_scan_ports']['192.168.1.99']
    total = finscan_ctx['stats']['total_packets']

    assert 1 <= scan['first_frame'] <= scan['last_frame'] <= total
    assert scan['first_ts'] <= scan['last_ts']


def test_scan_record_ports_are_in_first_seen_order(finscan_ctx):
    """Iterating 'ports' must walk forward in time - that IS the order."""
    steps = list(finscan_ctx['fin_scan_ports']['192.168.1.99']['ports'].values())

    frames = [frame for _, frame in steps]
    assert frames == sorted(frames)


def test_capture_time_span_recorded(finscan_ctx):
    stats = finscan_ctx['stats']

    assert stats['first_ts'] is not None
    assert stats['first_ts'] <= stats['last_ts']


# ======================================================================
# Modbus/TCP, on modbus_test.pcap.
#
# Every expected number below comes from tshark, not from this code:
#
#     tshark -r pcaps/modbus_test.pcap -Y "mbtcp && tcp.dstport==502" ...
#
# A test whose expectation was copied from the code's own output would
# only prove that the code agrees with itself.
#
# One deliberate disagreement with tshark: frames 91-109 are counted as
# Modbus responses here, while tshark shows them as plain "data". Byte
# for byte they are valid MBAP (exception responses from 10.0.0.8), so
# the parser is right to accept them.
# ======================================================================

def test_modbus_requests_per_master(modbus_ctx):
    masters = modbus_ctx['modbus']['masters']

    assert {ip: m['requests'] for ip, m in masters.items()} == {
        '10.0.0.57': 12,
        '10.0.0.9': 6,
        '10.1.1.234': 407,
        '192.168.66.235': 141,
    }


def test_modbus_responses_per_slave(modbus_ctx):
    slaves = modbus_ctx['modbus']['slaves']

    assert {ip: s['responses'] for ip, s in slaves.items()} == {
        '10.0.0.3': 16,
        '10.0.0.8': 10,           # frames 91-109, see the note above
        '166.161.16.230': 140,
        '10.10.5.85': 407,
    }


def test_modbus_function_code_sweep_is_visible(modbus_ctx):
    """The 2006 capture: one master, every function code from 0 to 127."""
    sweep = modbus_ctx['modbus']['masters']['192.168.66.235']

    assert sorted(sweep['function_codes']) == list(range(128))


def test_modbus_function_codes_keep_first_use_order(modbus_ctx):
    """Same contract as a scan record's 'ports': dict order = time order."""
    sweep = modbus_ctx['modbus']['masters']['192.168.66.235']

    frames = [frame for _, frame in sweep['function_codes'].values()]
    assert frames == sorted(frames)


def test_modbus_writes_collected(modbus_ctx):
    masters = modbus_ctx['modbus']['masters']

    scada = masters['10.1.1.234']['writes']
    assert len(scada) == 20
    assert {w['fc'] for w in scada} == {6}
    assert scada[0]['frame'] == 472          # the session opens with a write

    assert [w['fc'] for w in masters['10.0.0.9']['writes']] == [5, 5, 6]
    assert masters['10.0.0.57']['writes'] == []


def test_modbus_exceptions_per_slave(modbus_ctx):
    slaves = modbus_ctx['modbus']['slaves']

    assert slaves['166.161.16.230']['exceptions'] == {1: 104, 2: 8, 3: 18}
    assert slaves['10.0.0.3']['exceptions'] == {11: 4}
    assert slaves['10.10.5.85']['exceptions'] == {}


def test_modbus_malformed_frames(modbus_ctx):
    """On port 502, carrying data, and not valid MBAP.

    76, 78: length field 0x8804, far over the 254 limit
    80, 82: protocol id 0x0010
    111, 113: length 5 with 8 bytes after the field
    """
    frames = [m['frame'] for m in modbus_ctx['modbus']['malformed']]

    assert frames == [76, 78, 80, 82, 111, 113]


def test_modbus_every_payload_on_502_is_accounted_for(modbus_ctx):
    """Parsed or malformed - nothing on port 502 silently disappears.

    1145 = frames on port 502 with tcp.len > 0, counted by tshark. The
    same kind of invariant as the network-layer sum above.
    """
    modbus = modbus_ctx['modbus']

    assert modbus_ctx['stats']['modbus'] + len(modbus['malformed']) == 1145


def test_bare_acks_are_not_malformed(modbus_ctx):
    """Ethernet padding on a short ACK must not look like a payload.

    Frame 77 is a bare ACK from 10.0.0.8 padded to 60 bytes.
    """
    assert 77 not in [m['frame'] for m in modbus_ctx['modbus']['malformed']]


def test_no_modbus_in_a_capture_without_it(test_ctx):
    assert test_ctx['stats']['modbus'] == 0
    assert test_ctx['modbus'] == {'masters': {}, 'slaves': {}, 'malformed': [],
                                  'rejected_writes': []}


def test_config_starts_empty_and_feed_leaves_it_alone(modbus_ctx):
    """'config' is filled by main.py, never by the packets."""
    empty = {'modbus_masters': None, 'modbus_writers': None}
    assert make_context()['config'] == empty
    assert modbus_ctx['config'] == empty


def test_unauthorized_masters_on_modbus_test(modbus_ctx):
    """End to end: allow the 2012 SCADA master, expect the other three.

    Built on a copy of the context, because modbus_ctx is shared by the
    whole session and must stay as feed() left it.
    """
    from detectors import detect_modbus_unauthorized_master
    import ipaddress

    ctx = dict(modbus_ctx, config={
        'modbus_masters': [ipaddress.ip_network('10.1.1.234/32')],
        'modbus_writers': None,
    })

    findings = detect_modbus_unauthorized_master(ctx)

    assert sorted(f['source'] for f in findings) == ['10.0.0.57', '10.0.0.9', '192.168.66.235']


def test_fc_sweep_on_modbus_test(modbus_ctx):
    """End to end: exactly the 2006 sweep, nobody else, no flags needed."""
    from detectors import detect_modbus_fc_sweep

    findings = detect_modbus_fc_sweep(modbus_ctx)

    assert [f['source'] for f in findings] == ['192.168.66.235']
    assert findings[0]['function_codes'] == list(range(128))
    assert findings[0]['sequential'] is True
    assert findings[0]['first_frame'] == 124


def test_modbus_write_details_decoded(modbus_ctx):
    """Addresses and values from tshark's modbus.reference_num / regval."""
    writes = modbus_ctx['modbus']['masters']['10.1.1.234']['writes']

    by_frame = {w['frame']: w for w in writes}
    assert (by_frame[481]['address'], by_frame[481]['value']) == (500, 80)
    assert (by_frame[484]['address'], by_frame[484]['value']) == (502, 60)

    # The SCADA master only ever writes these five registers.
    assert {w['address'] for w in writes} == {100, 101, 102, 500, 502}
    assert not any(w['malformed'] for w in writes)


def test_modbus_malformed_writes_flagged(modbus_ctx):
    writes = modbus_ctx['modbus']['masters']['192.168.66.235']['writes']

    assert [w['frame'] for w in writes if w['malformed']] == [140, 163, 165, 180, 182]
    # The one well-formed write of the sweep: coil 0 OFF, which the device accepted.
    assert [(w['frame'], w['address'], w['value']) for w in writes if not w['malformed']] == [(138, 0, 0)]


def test_modbus_diagnostics_collected(modbus_ctx):
    diagnostics = modbus_ctx['modbus']['masters']['10.0.0.57']['diagnostics']

    assert [d['subfunction'] for d in diagnostics] == [4, 4, 4, 1, 1, 1, 10, 10]


def test_modbus_rejected_writes(modbus_ctx):
    rejected = modbus_ctx['modbus']['rejected_writes']

    assert [(r['frame'], r['fc'], r['code']) for r in rejected] == [
        (141, 6, 3), (164, 15, 3), (166, 16, 3), (181, 22, 3), (183, 23, 3),
    ]
    assert {r['master'] for r in rejected} == {'192.168.66.235'}


def test_dangerous_commands_on_modbus_test(modbus_ctx):
    """End to end: which master gets which reason - and who stays silent."""
    from detectors import detect_modbus_dangerous_command

    reasons = {}
    for f in detect_modbus_dangerous_command(modbus_ctx):
        reasons.setdefault(f['source'], set()).add(f['reason'])

    assert reasons == {
        '10.0.0.57': {'force_listen_only', 'restart_communications', 'clear_counters'},
        '192.168.66.235': {'malformed_write', 'rejected_write'},
    }
    # Not in the dict, on purpose: 10.1.1.234 (SCADA, 20 normal writes) and
    # 10.0.0.9 (three ordinary, accepted writes).


def test_unauthorized_writes_on_modbus_test(modbus_ctx):
    """Allow the SCADA master to write: 10.0.0.9 and the sweep are left.

    10.0.0.57 sends no write at all - its listen-only attack is the
    dangerous-command detector's catch, not this one's.
    """
    from detectors import detect_modbus_unauthorized_write
    import ipaddress

    ctx = dict(modbus_ctx, config={
        'modbus_masters': None,
        'modbus_writers': [ipaddress.ip_network('10.1.1.234/32')],
    })

    findings = {f['source']: f for f in detect_modbus_unauthorized_write(ctx)}

    assert set(findings) == {'10.0.0.9', '192.168.66.235'}
    assert [s['detail'] for s in findings['10.0.0.9']['timeline']] == [
        'coil 2 OFF', 'coil 1 OFF', 'reg 5 = 11',
    ]
