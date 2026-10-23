from __future__ import annotations

from ducktalk.nat import NatProfile, assess_socket
from ducktalk.stun import StunObservation


def observation(
    mapped: tuple[str, int] | None,
    *,
    local: tuple[str, int] = ("192.168.1.10", 5000),
    error: str | None = None,
) -> StunObservation:
    return StunObservation(
        server="stun.example:3478",
        family=4,
        mapped_ip=mapped[0] if mapped else None,
        mapped_port=mapped[1] if mapped else None,
        local_ip=local[0],
        local_port=local[1],
        rtt_ms=12.0 if mapped else None,
        error=error,
    )


def test_open_when_mapping_matches_local() -> None:
    row = observation(("8.8.8.8", 5000), local=("8.8.8.8", 5000))
    assessment = assess_socket(4, "8.8.8.8", 5000, [row])
    assert assessment.code == "open"


def test_port_mapping_same_ip() -> None:
    row = observation(("8.8.8.8", 6000), local=("8.8.8.8", 5000))
    assessment = assess_socket(4, "8.8.8.8", 5000, [row])
    assert assessment.code == "port_mapping"


def test_nat_when_public_ip_differs() -> None:
    assessment = assess_socket(4, "192.168.1.10", 5000, [observation(("1.1.1.1", 6000))])
    assert assessment.code == "nat"
    assert "1.1.1.1:6000" in " ".join(assessment.detail)


def test_symmetric_suspected_with_different_ports() -> None:
    rows = [
        observation(("1.1.1.1", 6000)),
        observation(("1.1.1.1", 6001)),
    ]
    assessment = assess_socket(4, "192.168.1.10", 5000, rows)
    assert assessment.code == "symmetric_suspected"


def test_multi_public_with_different_ips() -> None:
    rows = [
        observation(("1.1.1.1", 6000)),
        observation(("9.9.9.9", 6000)),
    ]
    assessment = assess_socket(4, "192.168.1.10", 5000, rows)
    assert assessment.code == "multi_public"


def test_cgnat_suspected() -> None:
    assessment = assess_socket(4, "100.64.1.10", 5000, [observation(("100.64.1.10", 6000))])
    assert assessment.code == "cgnat_suspected"


def test_udp_blocked_without_responses() -> None:
    assessment = assess_socket(4, "192.168.1.10", 5000, [observation(None, error="timeout")])
    assert assessment.code == "udp_blocked"


def test_not_tested_without_observations() -> None:
    assessment = assess_socket(4, "192.168.1.10", 5000, [])
    assert assessment.code == "not_tested"


def test_profile_summary_and_priority() -> None:
    profile = NatProfile.from_sockets(
        [
            (4, "192.168.1.10", 5000, [observation(("1.1.1.1", 6000))]),
            (6, "2001:db8::10", 5000, []),
        ],
        ["stun.example:3478"],
    )
    assert profile.primary_code() == "nat"
    assert "1.1.1.1:6000" in profile.summary()
    lines = profile.as_lines()
    assert any("Limitations" in line for line in lines)
    assert any("No port prediction" in line for line in lines)
