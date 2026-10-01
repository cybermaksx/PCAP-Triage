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



    if len(payload) < MIN_MESSAGE_LEN:
        return None

    

    transaction_id, protocol_id, length, unit_id = struct.unpack(
            '>HHHB', payload[:MBAP_HEADER_LEN])


    if protocol_id != 0:
        return None

    if not (MIN_LENGTH_FIELD <= length <= MAX_LENGTH_FIELD):
            return None

    if length != len(payload) - 6:
            return None
    
    fc = payload[MBAP_HEADER_LEN]
    is_exception = False
    exception_code = None
    
    if fc & EXCEPTION_BIT:
        is_exception = True
        fc = fc & ~EXCEPTION_BIT
        if len(payload) > MBAP_HEADER_LEN + 1:
            exception_code = payload[MBAP_HEADER_LEN + 1]

    return {
            'transaction_id': transaction_id,
            'unit_id':        unit_id,
            'function_code':  fc,
            'is_exception':   is_exception,
            'exception_code': exception_code,
            'data':           payload[MBAP_HEADER_LEN + 1:],
        }


# ======================================================================
# WHAT A WRITE OR A DIAGNOSTIC REQUEST SAYS
#
# parse_mbap() stops at the function code and hands back the rest as
# 'data'. What that data MEANS depends on the function code, so it is
# decoded here, one function at a time, and only for the requests the
# dangerous-command detector looks at.
#
# Every layout below is a REQUEST layout. A response to a write either
# echoes the request or is an exception - and for an exception, the
# function code and exception code from parse_mbap() are all that matter.
# ======================================================================

# Function code 8 is a family of commands chosen by a 2-byte subfunction.
# Most are harmless counters; these three change the device's state.
DIAG_RESTART_COMMUNICATIONS = 1     # restarts the serial port, ends listen-only
DIAG_FORCE_LISTEN_ONLY = 4          # device stops answering ANYONE until restarted
DIAG_CLEAR_COUNTERS = 10            # wipes the diagnostic counters - and the evidence

DIAGNOSTIC_NAMES = {
    0:  'Return Query Data',
    DIAG_RESTART_COMMUNICATIONS: 'Restart Communications Option',
    2:  'Return Diagnostic Register',
    DIAG_FORCE_LISTEN_ONLY: 'Force Listen Only Mode',
    DIAG_CLEAR_COUNTERS: 'Clear Counters and Diagnostic Register',
}

# The only two values Write Single Coil accepts: ON and OFF. Anything else
# is a protocol violation the device must reject.
COIL_ON = 0xFF00
COIL_OFF = 0x0000

# Per-request limits from the specification. A request beyond them is not
# a big write, it is an invalid one.
MAX_WRITE_COILS = 1968          # FC 15
MAX_WRITE_REGISTERS = 123       # FC 16
MAX_READWRITE_REGISTERS = 121   # FC 23, write half


def parse_write(fc, data):
    """Decode the data of a write request.

    Arguments:
        fc   -- function code, one of WRITE_FCS
        data -- the 'data' field returned by parse_mbap()

    Returns:
        {
            'space':    'coil' or 'register',   # coils and registers are
                                                # separate address spaces
            'address':  100,                    # first address written
            'quantity': 1,                      # how many from there on
            'value':    80,                     # FC 5 / FC 6 only, else None
        }

    ...or None when the data does not fit the layout of that function -
    too short, too long, a count that disagrees with the bytes present.
    A write the device cannot even parse is a fact worth reporting, so
    None here means "malformed", not "ignore".

    Layouts (all big-endian, after the function code):

        FC 5   address(2) value(2)
        FC 6   address(2) value(2)
        FC 15  address(2) quantity(2) byte_count(1) values(byte_count)
        FC 16  address(2) quantity(2) byte_count(1) values(byte_count)
        FC 22  address(2) and_mask(2) or_mask(2)
        FC 23  read_address(2) read_quantity(2)
               write_address(2) write_quantity(2) byte_count(1) values(...)
    """
    if fc in (5, 6):
        if len(data) != 4:
            return None
        address, value = struct.unpack('>HH', data)
        return {'space': 'coil' if fc == 5 else 'register',
                'address': address, 'quantity': 1, 'value': value}

    if fc in (15, 16):
        if len(data) < 5:
            return None
        address, quantity, byte_count = struct.unpack('>HHB', data[:5])

        # Coils are packed 8 to a byte, registers take 2 bytes each.
        if fc == 15:
            limit, expected_bytes = MAX_WRITE_COILS, (quantity + 7) // 8
        else:
            limit, expected_bytes = MAX_WRITE_REGISTERS, quantity * 2

        # Three numbers that must agree: quantity within the limit, the
        # byte count it implies, and the bytes actually present.
        if not (1 <= quantity <= limit):
            return None
        if byte_count != expected_bytes or len(data) - 5 != byte_count:
            return None
        return {'space': 'coil' if fc == 15 else 'register',
                'address': address, 'quantity': quantity, 'value': None}

    if fc == 22:
        if len(data) != 6:
            return None
        address = struct.unpack('>H', data[:2])[0]
        return {'space': 'register', 'address': address, 'quantity': 1, 'value': None}

    if fc == 23:
        if len(data) < 9:
            return None
        _, _, address, quantity, byte_count = struct.unpack('>HHHHB', data[:9])
        if not (1 <= quantity <= MAX_READWRITE_REGISTERS):
            return None
        if byte_count != quantity * 2 or len(data) - 9 != byte_count:
            return None
        return {'space': 'register', 'address': address, 'quantity': quantity, 'value': None}

    # Not a write function code at all - a caller mistake, not bad data.
    raise ValueError(f"parse_write: function code {fc} is not a write")


def parse_diagnostic(data):
    """The subfunction of an FC 8 request, or None if the data is too short.

        FC 8   subfunction(2) data(2, usually)
    """
    if len(data) < 2:
        return None
    return struct.unpack('>H', data[:2])[0]
