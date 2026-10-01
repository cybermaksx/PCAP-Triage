"""Tests for the Modbus/TCP parser (modbus.py).

parse_mbap() is a pure function - bytes in, dict or None out - so every
test here builds its input by hand with bytes.fromhex(). No capture, no
scapy. The spaces in the hex strings are only for reading; fromhex()
ignores them. They are grouped as the MBAP header is laid out:

    trans  proto  length  unit  FC  data
    0001   0000   0006    ff    06  0064 0000
"""

import random

import pytest

from modbus import EXCEPTION_BIT, WRITE_FCS, parse_diagnostic, parse_mbap, parse_write


# ======================================================================
# Well-formed messages
# ======================================================================

def test_parses_a_write_single_register_request():
    message = parse_mbap(bytes.fromhex('0001 0000 0006 ff 06 0064 0000'))

    assert message == {
        'transaction_id': 1,
        'unit_id': 255,
        'function_code': 6,
        'is_exception': False,
        'exception_code': None,
        'data': bytes.fromhex('0064 0000'),
    }


def test_reads_fields_big_endian():
    """0x1234 must come out as 4660, not 13330 (0x3412, little-endian)."""
    message = parse_mbap(bytes.fromhex('1234 0000 0002 01 03'))

    assert message['transaction_id'] == 0x1234


def test_message_with_no_data_after_the_function_code():
    """length 2 = unit id + FC only. The smallest valid message."""
    message = parse_mbap(bytes.fromhex('0001 0000 0002 01 11'))

    assert message['function_code'] == 17
    assert message['data'] == b''


# ======================================================================
# Exceptions
# ======================================================================

def test_exception_response_strips_the_bit_and_reads_the_code():
    """0x81 = 'FC 1 failed', followed by exception code 1."""
    message = parse_mbap(bytes.fromhex('0001 0000 0003 01 81 01'))

    assert message['is_exception'] is True
    assert message['function_code'] == 1          # not 0x81 = 129
    assert message['exception_code'] == 1


def test_truncated_exception_has_no_code_and_does_not_raise():
    """The bit is set but the code byte never arrived."""
    message = parse_mbap(bytes.fromhex('0001 0000 0002 01 81'))

    assert message['is_exception'] is True
    assert message['exception_code'] is None


@pytest.mark.parametrize("fc", range(0, 128))
def test_no_function_code_below_128_is_an_exception(fc):
    """Guards the bit test: '& 0x80', not '> 0' or '== 0x80'.

    The 2006 capture in modbus_test.pcap requests every one of 0..127.
    """
    message = parse_mbap(bytes.fromhex('0001 0000 0002 01') + bytes([fc]))

    assert message['is_exception'] is False
    assert message['function_code'] == fc


# ======================================================================
# Not Modbus -> None
# ======================================================================

@pytest.mark.parametrize("hex_payload, why", [
    ('',                              'empty'),
    ('0001 0000 0006',                'shorter than a header'),
    ('0001 0000 0002 01',             'header but no function code'),
    ('0001 0001 0006 ff 06 0064 0000', 'protocol id is not 0'),
    ('0001 0000 0001 01 03',          'length below 2'),
    ('0001 0000 0007 ff 06 0064 0000', 'length says more than is there'),
    ('0001 0000 0005 ff 06 0064 0000', 'length says less than is there'),
    ('0001 0000 0010 0a 01 00 01 00 03', 'frame 80 of modbus_test.pcap'),
])
def test_rejects(hex_payload, why):
    assert parse_mbap(bytes.fromhex(hex_payload)) is None, why


def test_rejects_length_above_254():
    """255 is consistent with the bytes present, but over the spec limit."""
    payload = bytes.fromhex('0001 0000 00ff 01 03') + bytes(253)

    assert len(payload) - 6 == 255
    assert parse_mbap(payload) is None


def test_never_raises_on_garbage():
    """feed() calls this on every payload on port 502, whatever it holds.

    A fixed seed keeps the run reproducible: if it ever fails, the same
    input fails again.
    """
    rng = random.Random(502)

    for _ in range(5000):
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        result = parse_mbap(payload)
        assert result is None or isinstance(result, dict)


# ======================================================================
# Tables
# ======================================================================

def test_write_fcs_do_not_include_reads():
    assert WRITE_FCS.isdisjoint({1, 2, 3, 4})
    assert EXCEPTION_BIT == 0x80


# ======================================================================
# parse_write - the data of a write request, after the function code.
# The hex below is ONLY that data part.
# ======================================================================

@pytest.mark.parametrize("fc, hex_data, expected", [
    # FC 6, register 500 = 80: frame 481 of modbus_test.pcap
    (6,  '01f4 0050',                  {'space': 'register', 'address': 500, 'quantity': 1, 'value': 80}),
    # FC 5, coil 2 OFF: frame 60
    (5,  '0002 0000',                  {'space': 'coil', 'address': 2, 'quantity': 1, 'value': 0}),
    (5,  '0002 ff00',                  {'space': 'coil', 'address': 2, 'quantity': 1, 'value': 0xFF00}),
    # FC 15, 10 coils from 0: 2 bytes of packed bits
    (15, '0000 000a 02 ff03',          {'space': 'coil', 'address': 0, 'quantity': 10, 'value': None}),
    # FC 16, 2 registers from 100
    (16, '0064 0002 04 0001 0002',     {'space': 'register', 'address': 100, 'quantity': 2, 'value': None}),
    # FC 22, mask write register 4
    (22, '0004 00f2 0025',             {'space': 'register', 'address': 4, 'quantity': 1, 'value': None}),
    # FC 23, read 6 from 3, write 3 to 14
    (23, '0003 0006 000e 0003 06 00ff 00ff 00ff',
                                       {'space': 'register', 'address': 14, 'quantity': 3, 'value': None}),
])
def test_parse_write_valid(fc, hex_data, expected):
    assert parse_write(fc, bytes.fromhex(hex_data)) == expected


@pytest.mark.parametrize("fc, hex_data, why", [
    # The five malformed writes of the 2006 sweep, frames 140-182
    (6,  '0000 0000 0000',             'FC 6 with two extra bytes (frame 140)'),
    (15, '0000 0000 00',               'FC 15 quantity 0 (frame 163)'),
    (16, '0000 0000 00',               'FC 16 quantity 0 (frame 165)'),
    (22, '0000 0000',                  'FC 22 without the or-mask (frame 180)'),
    (23, '0000 0000',                  'FC 23 cut off after the read half (frame 182)'),
    # Counts that disagree
    (16, '0064 0002 02 0001',          'byte count says 1 register, quantity says 2'),
    (16, '0064 0002 04 0001',          'byte count 4, only 2 bytes present'),
    (15, '0000 000a 01 ff',            '10 coils need 2 bytes, not 1'),
    (16, '0000 007c f8' + '00' * 248,  '124 registers, over the limit of 123'),
    (5,  '0002',                       'FC 5 without a value'),
])
def test_parse_write_malformed(fc, hex_data, why):
    assert parse_write(fc, bytes.fromhex(hex_data)) is None, why


def test_parse_write_refuses_a_non_write_code():
    """A caller bug, not bad data - so it raises instead of returning None."""
    with pytest.raises(ValueError):
        parse_write(3, bytes.fromhex('0000 0001'))


def test_parse_diagnostic():
    assert parse_diagnostic(bytes.fromhex('0004 0000')) == 4      # frame 8
    assert parse_diagnostic(bytes.fromhex('000a 0000')) == 10     # frame 23
    assert parse_diagnostic(bytes.fromhex('00')) is None
