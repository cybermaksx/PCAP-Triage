"""Shared setup for the test suite.

pytest imports this file automatically before collecting any tests in
this directory - it never has to be imported by hand.

RUNNING THE SUITE
-----------------
    ./venv/bin/python -m pytest tests/ -v

The "-m" matters. A bare "pytest tests/" fails with

    ModuleNotFoundError: No module named 'context'

because it does not put the current directory on the module search path,
so "from context import ..." below cannot find the project. Always run
from the repository root, always through "python -m".
"""

from pathlib import Path

import pytest
from scapy.all import rdpcap

from context import make_context, feed


# Captures are located relative to THIS file, not to the current working
# directory. That way the suite passes no matter where it is started from.
PCAP_DIR = Path(__file__).resolve().parent.parent / "pcaps"


def build_context(name):
    """Run one capture through the pipeline and return the finished ctx.

    These are the same four lines main.py runs. They live here so that no
    individual test has to repeat them.

    Note the name does NOT start with "test_", so pytest treats this as a
    plain helper rather than as a test case.
    """
    ctx = make_context()
    for index, packet in enumerate(rdpcap(str(PCAP_DIR / name))):
        feed(ctx, packet, index)
    return ctx


# ----------------------------------------------------------------------
# Fixtures.
#
# A fixture is a value a test can ask for by naming it as an argument:
#
#     def test_something(test_ctx):    <- pytest calls test_ctx() and
#         assert test_ctx[...]            passes the result in
#
# scope="session" means the capture is parsed ONCE for the whole run and
# reused by every test that asks for it. Without it, synscan.pcapng
# (131 428 packets) would be re-read for each individual assertion.
# ----------------------------------------------------------------------

@pytest.fixture(scope="session")
def test_ctx():
    return build_context("test.pcapng")


@pytest.fixture(scope="session")
def finscan_ctx():
    return build_context("finscan.pcapng")


@pytest.fixture(scope="session")
def synscan_ctx():
    return build_context("synscan.pcapng")
