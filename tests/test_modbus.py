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

from modbus import EXCEPTION_BIT, WRITE_FCS, parse_mbap


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
