from __future__ import annotations

import socket
import threading

import pytest

from ducktalk.stun import (
    ATTR_FINGERPRINT,
    ATTR_MESSAGE_INTEGRITY,
    ATTR_USERNAME,
    BINDING_REQUEST,
    StunError,
    build_binding_request,
    build_binding_success,
    decode_mapped_address,
    decode_xor_mapped_address,
    encode_mapped_address,
    encode_xor_mapped_address,
    has_valid_fingerprint,
    message_integrity_valid,
    parse_message,
    parse_server_spec,
    stun_discover_on_socket,
    transaction_id,
)


def test_xor_mapped_address_round_trip_v4() -> None:
    txid = transaction_id()
    encoded = encode_xor_mapped_address("192.0.2.44", 54321, txid)
    assert decode_xor_mapped_address(encoded, txid) == ("192.0.2.44", 54321)


def test_xor_mapped_address_round_trip_v6() -> None:
    txid = transaction_id()
    encoded = encode_xor_mapped_address("2001:db8::1234", 443, txid)
    assert decode_xor_mapped_address(encoded, txid) == ("2001:db8::1234", 443)


def test_mapped_address_round_trip() -> None:
    encoded = encode_mapped_address("198.51.100.7", 8080)
    assert decode_mapped_address(encoded) == ("198.51.100.7", 8080)


def test_binding_request_integrity_and_fingerprint() -> None:
    password = b"session-secret"
    raw, txid = build_binding_request(
        username="ducktalk:abc",
        password=password,
        priority=1234,
        controlling=True,
        tiebreaker=99,
        use_candidate=True,
    )
    message = parse_message(raw)
    assert message.message_type == BINDING_REQUEST
    assert message.transaction_id == txid
    assert message.get(ATTR_USERNAME) == b"ducktalk:abc"
    assert message_integrity_valid(message, password)
    assert not message_integrity_valid(message, b"wrong-secret")
    assert has_valid_fingerprint(message)


def test_tampered_mi_fails() -> None:
    password = b"session-secret"
    raw, _ = build_binding_request(username="u", password=password)
    message = parse_message(raw)
    attribute = next(a for a in message.attributes if a.type == ATTR_MESSAGE_INTEGRITY)
    tampered = bytearray(raw)
    tampered[attribute.offset + 4] ^= 0xFF
    tampered_message = parse_message(bytes(tampered))
    assert not message_integrity_valid(tampered_message, password)


def test_parse_rejects_bad_cookie_and_alignment() -> None:
    with pytest.raises(StunError):
        parse_message(b"\x00" * 20)
    raw, _ = build_binding_request()
    with pytest.raises(StunError):
        parse_message(raw + b"\x00")


def test_parse_server_spec() -> None:
    assert parse_server_spec("stun.example.com:19302") == ("stun.example.com", 19302)
    assert parse_server_spec("stun.example.com") == ("stun.example.com", 3478)
    with pytest.raises(ValueError):
        parse_server_spec("host:notaport")
    with pytest.raises(ValueError):
        parse_server_spec("host:99999")


def test_discovery_against_local_fake_server() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(2.0)
    server_address = server.getsockname()
    stop = threading.Event()

    def fake_server() -> None:
        try:
            while not stop.is_set():
                try:
                    data, source = server.recvfrom(4096)
                except TimeoutError:
                    continue
                except OSError:
                    return
                request = parse_message(data)
                if request.message_type != BINDING_REQUEST:
                    continue
                response = build_binding_success(
                    request.transaction_id,
                    "203.0.113.9",
                    45678,
                )
                server.sendto(response, source)
        finally:
            server.close()

    thread = threading.Thread(target=fake_server, daemon=True)
    thread.start()
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    try:
        observation = stun_discover_on_socket(
            client,
            f"127.0.0.1:{server_address[1]}",
            family=4,
            timeout=1.0,
        )
    finally:
        client.close()
        stop.set()
        thread.join(timeout=2.0)
    assert observation.ok
    assert observation.mapped == ("203.0.113.9", 45678)
    assert observation.rtt_ms is not None


def test_discovery_rejects_bad_fingerprint() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(2.0)
    server_address = server.getsockname()

    def fake_server() -> None:
        try:
            data, source = server.recvfrom(4096)
            request = parse_message(data)
            response = bytearray(
                build_binding_success(request.transaction_id, "203.0.113.9", 45678)
            )
            parsed = parse_message(bytes(response))
            attribute = next(a for a in parsed.attributes if a.type == ATTR_FINGERPRINT)
            response[attribute.offset + 4] ^= 0xFF
            server.sendto(bytes(response), source)
        finally:
            server.close()

    thread = threading.Thread(target=fake_server, daemon=True)
    thread.start()
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    try:
        observation = stun_discover_on_socket(
            client,
            f"127.0.0.1:{server_address[1]}",
            family=4,
            timeout=1.0,
        )
    finally:
        client.close()
        thread.join(timeout=2.0)
    assert not observation.ok
    assert "fingerprint" in (observation.error or "").lower()
