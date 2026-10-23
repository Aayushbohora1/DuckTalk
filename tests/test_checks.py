from __future__ import annotations

import time

from ducktalk.candidates import make_candidate
from ducktalk.checks import CheckManager
from ducktalk.transport import UdpEndpoint


def test_connectivity_check_succeeds_between_two_endpoints() -> None:
    left = UdpEndpoint(4, "127.0.0.1", "udp4")
    right = UdpEndpoint(4, "127.0.0.1", "udp4")
    username = "ducktalk:test"
    password = b"token" * 4
    left_checks = CheckManager(
        {"udp4": left},
        {"udp4": "left-host"},
        username,
        password,
        controlling=True,
        tiebreaker=1,
    )
    right_checks = CheckManager(
        {"udp4": right},
        {"udp4": "right-host"},
        username,
        password,
        controlling=False,
        tiebreaker=2,
    )
    left.start(lambda data, source: left_checks.handle(data, source, left))
    right.start(lambda data, source: right_checks.handle(data, source, right))
    left_checks.start()
    right_checks.start()
    candidate = make_candidate(
        cid="right",
        protocol="udp",
        kind="host",
        address="127.0.0.1",
        port=right.local_port,
        local_key="udp4",
    )
    try:
        left_checks.add_candidate(candidate)
        deadline = time.monotonic() + 3.0
        successes = []
        while time.monotonic() < deadline and not successes:
            successes = left_checks.successful()
            time.sleep(0.05)
        assert successes
        target = successes[0]
        assert target.status == "succeeded"
        assert target.rtt_ms is not None
        assert target.remote == ("127.0.0.1", right.local_port)
    finally:
        left_checks.stop()
        right_checks.stop()
        left.close()
        right.close()
