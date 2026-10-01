"""
PROTOCOL KNOWLEDGE — MODBUS/TCP
===============================

This module knows what a Modbus/TCP message looks like. That is all it knows.

It does not know about packets, scapy, the context or findings. It is handed
raw bytes (the TCP payload) and says either "here are the fields" or "this is
not Modbus". Everything else - who sent it, when, whether it is suspicious -
belongs to context.py and detectors.py.

Why a separate file
-------------------
context.py collects facts about MANY protocols. If the byte layout of every
protocol lived inside feed(), that function would become a wall of offsets.
Here the protocol knowledge has one home, and parse_mbap() is a pure function:
bytes in, dict out. That makes it testable without any capture at all:

    parse_mbap(bytes.fromhex('0001 0000 0006 ff 06 0064 0000'))

Dependency direction: context.py imports this file, never the other way round.
This file imports nothing from the project.

THE MESSAGE LAYOUT
------------------
Every Modbus/TCP message is a 7-byte MBAP header followed by the PDU
(function code + data). All numbers are big-endian (most significant byte
first - "network byte order").

     offset  0      2      4      6    7     8
            ┌──────┬──────┬──────┬────┬─────┬────────────┐
            │trans │proto │length│unit│ FC  │ data ...   │
            │  id  │  id  │      │ id │     │            │
            └──────┴──────┴──────┴────┴─────┴────────────┘
     bytes     2      2      2     1     1     0..252

    transaction id  - chosen by the master, echoed back in the response;
                      pairs a response with its request
    protocol id     - ALWAYS 0 for Modbus. Anything else is not Modbus
    length          - number of bytes AFTER this field: unit id + FC + data.
                      So for a well-formed message:  length == len(payload) - 6
    unit id         - the slave address behind a gateway. 255 or 0 when the
                      TCP device is the slave itself
    function code   - what is being asked: read coils, write register, ...
                      In a RESPONSE, the high bit (0x80) set means "error":
                      0x86 = an exception in reply to FC 6, and the next byte
                      is the exception code

Request or response is NOT written in the message. It follows from the
direction: a request goes TO port 502, a response comes FROM port 502.
That decision is made in context.py, which can see the ports.
"""

import struct


# ======================================================================
# CONSTANTS
# ======================================================================

# The registered Modbus/TCP port. NOTE: real installations do move it, which
# is why parse_mbap() does not look at ports at all - only context.py does.
MODBUS_PORT = 502

MBAP_HEADER_LEN = 7

# Smallest message that carries a function code: 7 header bytes + 1 FC byte.
MIN_MESSAGE_LEN = MBAP_HEADER_LEN + 1

# Limits on the 'length' field. At least 2 (unit id + FC). At most 254: the
# Modbus PDU is capped at 253 bytes by the specification, plus 1 for unit id.
MIN_LENGTH_FIELD = 2
MAX_LENGTH_FIELD = 254

# The high bit of the function code in a response marks an exception.
EXCEPTION_BIT = 0x80

# Function codes that CHANGE something on the device. These are what an
# operator worries about: reading a register is observation, writing one
# moves a valve.
WRITE_FCS = {
    5,    # Write Single Coil
    6,    # Write Single Register
    15,   # Write Multiple Coils
    16,   # Write Multiple Registers
    22,   # Mask Write Register
    23,   # Read/Write Multiple Registers
}

# Human-readable names, for the report. Anything not listed here is either
# vendor-specific or not a real function code at all - the 2006 capture in
# modbus_test.pcap walks through all of 0..127 exactly to find out which
# ones a device accepts.
FUNCTION_NAMES = {
    1:  'Read Coils',
    2:  'Read Discrete Inputs',
    3:  'Read Holding Registers',
    4:  'Read Input Registers',
    5:  'Write Single Coil',
    6:  'Write Single Register',
    7:  'Read Exception Status',
    8:  'Diagnostics',
    11: 'Get Comm Event Counter',
    12: 'Get Comm Event Log',
    15: 'Write Multiple Coils',
    16: 'Write Multiple Registers',
    17: 'Report Server ID',
    20: 'Read File Record',
    21: 'Write File Record',
    22: 'Mask Write Register',
    23: 'Read/Write Multiple Registers',
    24: 'Read FIFO Queue',
    43: 'Encapsulated Interface Transport',   # incl. Read Device Identification
}

EXCEPTION_NAMES = {
    1:  'Illegal Function',
    2:  'Illegal Data Address',
    3:  'Illegal Data Value',
    4:  'Server Device Failure',
    5:  'Acknowledge',
    6:  'Server Device Busy',
    8:  'Memory Parity Error',
    10: 'Gateway Path Unavailable',
    11: 'Gateway Target Device Failed to Respond',
}


# ======================================================================
# THE PARSER
# ======================================================================

def parse_mbap(payload):
    """Parse one Modbus/TCP message from a TCP payload.

    Arguments:
        payload -- bytes, the TCP payload. In feed() that is
                   bytes(packet[TCP].payload)

    Returns a dict:
        {
            'transaction_id': 1,
            'unit_id':        255,
            'function_code':  6,       # with the exception bit REMOVED
            'is_exception':   False,
            'exception_code': None,    # int when is_exception is True
            'data':           b'\\x00d\\x00\\x00',   # everything after the FC
        }

    ...or None when the bytes are not a well-formed Modbus message.
    None, never an exception: feed() runs on every packet of a capture, and
    one malformed packet must not end the whole analysis. Scanners send
    garbage on purpose - frames 180 and 182 in modbus_test.pcap are exactly
    that, and 10.0.0.8 answers on port 502 with something that is not Modbus
    at all (frames 91-113).
    """

    # ------------------------------------------------------------------
    # STEP 1 - is there enough data for a header and a function code?
    #
    # Check BEFORE touching any offsets. Unpacking 7 bytes out of a
    # 5-byte payload raises struct.error.
    #
    # TODO: if the payload is shorter than MIN_MESSAGE_LEN, return None
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # STEP 2 - unpack the MBAP header.
    #
    # One struct.unpack call reads all four fields:
    #
    #     '>'  big-endian
    #     'H'  unsigned 2-byte integer   (transaction id)
    #     'H'  unsigned 2-byte integer   (protocol id)
    #     'H'  unsigned 2-byte integer   (length)
    #     'B'  unsigned 1-byte integer   (unit id)
    #
    # TODO: transaction_id, protocol_id, length, unit_id = struct.unpack(...)
    #       on the first MBAP_HEADER_LEN bytes of the payload
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # STEP 3 - validate. This is what separates Modbus from "something on
    # port 502". Return None if ANY of these fails:
    #
    #   a) protocol_id must be 0
    #   b) length must be within MIN_LENGTH_FIELD..MAX_LENGTH_FIELD
    #   c) length must agree with the bytes actually present:
    #          length == len(payload) - 6
    #      (6, not 7: 'length' counts the unit id byte, which is the 7th
    #       byte of the header)
    #
    # NOTE on (c): one TCP segment can carry SEVERAL Modbus messages back
    # to back, and one message can be split across two segments. Requiring
    # an exact match ignores both cases for now - write that down as a
    # known limitation rather than half-handling it.
    #
    # TODO: the three checks
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # STEP 4 - function code and exception bit.
    #
    # The FC is the byte right after the header: payload[MBAP_HEADER_LEN].
    # Indexing bytes gives an int directly, no unpack needed.
    #
    # If the EXCEPTION_BIT is set:
    #     is_exception   = True
    #     function_code  = fc without the bit      (fc & ~EXCEPTION_BIT,
    #                                               or fc - 0x80)
    #     exception_code = the next byte, IF it is there - a truncated
    #                      exception response must not raise IndexError
    #
    # Why strip the bit: "FC 6 failed" and "FC 6 succeeded" are both
    # about FC 6. Counting 0x86 as a separate function code 134 would
    # split one function across two buckets.
    #
    # TODO: fc, is_exception, exception_code
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # STEP 5 - build and return the dict described in the docstring.
    # 'data' is everything after the function code.
    #
    # TODO: return {...}
    # ------------------------------------------------------------------

    raise NotImplementedError("parse_mbap: steps 1-5 above")
