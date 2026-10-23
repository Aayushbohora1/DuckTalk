from __future__ import annotations

import time

import pytest

from ducktalk.candidates import (
    Candidate,
    Invite,
    InviteError,
    b64d,
    b64e,
    candidate_priority,
    gather_host_addresses,
    make_candidate,
    sanitize_name,
    sort_candidates,
)


def sample_candidates() -> list[Candidate]:
    return [
        make_candidate(
            cid="u4h",
            protocol="udp",
            kind="host",
            address="192.0.2.10",
            port=5000,
            local_key="udp4",
        ),
        make_candidate(
            cid="t4h",
            protocol="tcp",
            kind="host",
            address="192.0.2.10",
            port=6000,
            local_key="tcp4",
        ),
        make_candidate(
            cid="u6h",
            protocol="udp",
            kind="host",
            address="2001:db8::10",
            port=5000,
            local_key="udp6",
        ),
    ]


def sample_invite() -> Invite:
    now = int(time.time())
    return Invite(
        session_id=b"\x01" * 16,
        token=b"\x02" * 16,
        name="Alice",
        static_public=b"\x03" * 32,
        candidates=sample_candidates(),
        created_at=now,
        expires_at=now + 600,
    )


def test_invite_round_trip() -> None:
    invite = sample_invite()
    code = invite.encode()
    assert code.startswith("DTK1-")
    decoded = Invite.decode(code)
    assert decoded.session_id == invite.session_id
    assert decoded.token == invite.token
    assert decoded.name == invite.name
    assert decoded.static_public == invite.static_public
    assert {c.id for c in decoded.candidates} == {c.id for c in invite.candidates}


def test_invite_rejects_expired() -> None:
    invite = sample_invite()
    with pytest.raises(InviteError):
        Invite.decode(invite.encode(), now=invite.expires_at + 1)


def test_invite_rejects_garbage_and_wrong_prefix() -> None:
    with pytest.raises(InviteError):
        Invite.decode("not-an-invite")
    with pytest.raises(InviteError):
        Invite.decode("DTK1-!!!!")


def test_invite_rejects_duplicate_candidate_ids() -> None:
    invite = sample_invite()
    data = invite.to_json()
    data["candidates"].append(dict(data["candidates"][0]))
    import json

    raw = json.dumps(data, separators=(",", ":")).encode()
    with pytest.raises(InviteError):
        Invite.decode("DTK1-" + b64e(raw))


def test_candidate_rejects_relay_and_bad_addresses() -> None:
    base = {
        "id": "x",
        "proto": "udp",
        "kind": "relay",
        "addr": "192.0.2.1",
        "port": 1234,
        "family": 4,
        "priority": 1,
    }
    with pytest.raises(InviteError):
        Candidate.from_json(base)
    for key, value in (
        ("port", 0),
        ("family", 5),
        ("addr", "not-an-ip"),
        ("addr", "2001:db8::1"),
        ("proto", "sctp"),
    ):
        item = dict(base)
        item["kind"] = "host"
        item[key] = value
        with pytest.raises(InviteError):
            Candidate.from_json(item)


def test_candidate_rejects_link_local_ipv6() -> None:
    with pytest.raises(InviteError):
        Candidate.from_json(
            {
                "id": "x",
                "proto": "udp",
                "kind": "host",
                "addr": "fe80::1",
                "port": 1234,
                "family": 6,
                "priority": 1,
            }
        )


def test_candidate_priority_prefers_udp_and_ipv6() -> None:
    udp6 = candidate_priority("host", 6, "2001:db8::1", "udp")
    udp4 = candidate_priority("host", 4, "192.0.2.1", "udp")
    tcp4 = candidate_priority("host", 4, "192.0.2.1", "tcp")
    relay = candidate_priority("relay", 4, "192.0.2.1", "udp")
    assert udp6 > udp4 > tcp4 > relay


def test_sort_candidates_orders_by_priority() -> None:
    ordered = sort_candidates(sample_candidates())
    assert ordered[0].id == "u6h"
    assert ordered[-1].id == "t4h"


def test_b64_helpers_are_urlsafe_and_unpadded() -> None:
    data = b"\xfb\xff\xfe"
    encoded = b64e(data)
    assert "=" not in encoded
    assert b64d(encoded) == data


def test_sanitize_name() -> None:
    assert sanitize_name("  Alice\n") == "Alice"
    assert sanitize_name("") == "peer"
    assert len(sanitize_name("x" * 100)) == 40
    assert sanitize_name("\x00\x01") == "peer"


def test_gather_host_addresses_no_loopback_by_default() -> None:
    addresses = gather_host_addresses(4, allow_loopback=False)
    assert "127.0.0.1" not in addresses
    with_loopback = gather_host_addresses(4, allow_loopback=True)
    assert "127.0.0.1" in with_loopback
