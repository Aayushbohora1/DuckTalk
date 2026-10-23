from __future__ import annotations

import socket
import threading
import time

import pytest

from ducktalk.paths import TcpPath
from ducktalk.transport import (
    FRAME_DATA,
    TcpPathSecureChannel,
    TransportError,
    UdpEndpoint,
    UdpSecureChannel,
)


def test_udp_secure_channel_delivers_encrypted_chat() -> None:
    left = UdpEndpoint(4, "127.0.0.1", "left")
    right = UdpEndpoint(4, "127.0.0.1", "right")
    received: list[tuple[int, bytes]] = []
    ready = threading.Event()
    key_a = b"a" * 32
    key_b = b"b" * 32
    channel_a = UdpSecureChannel(
        left,
        ("127.0.0.1", right.local_port),
        key_a,
        key_b,
        on_frame=lambda frame_type, payload: None,
        on_close=lambda reason: None,
    )
    channel_b = UdpSecureChannel(
        right,
        ("127.0.0.1", left.local_port),
        key_b,
        key_a,
        on_frame=lambda frame_type, payload: (
            received.append((frame_type, payload)),
            ready.set(),
        ),
        on_close=lambda reason: None,
    )
    right.start(lambda data, source: channel_b.receive(data, source))
    left.start(lambda data, source: channel_a.receive(data, source))
    try:
        channel_a.start()
        channel_b.start()
        assert channel_a.wait_ready(3.0)
        assert channel_b.wait_ready(3.0)
        channel_a.send_chat("secret message")
        assert ready.wait(3.0)
        assert received == [(FRAME_DATA, b"secret message")]
    finally:
        channel_a.close()
        channel_b.close()
        left.close()
        right.close()


def test_udp_secure_channel_rejects_oversized_message() -> None:
    endpoint = UdpEndpoint(4, "127.0.0.1", "left")
    channel = UdpSecureChannel(
        endpoint,
        ("127.0.0.1", 9),
        b"a" * 32,
        b"b" * 32,
        on_frame=lambda frame_type, payload: None,
        on_close=lambda reason: None,
    )
    try:
        with pytest.raises(TransportError):
            channel.send_chat("x" * 901)
    finally:
        channel.close()
        endpoint.close()


def test_tcp_path_secure_channel_buffers_early_packets() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3.0)
    port = listener.getsockname()[1]
    accepted: dict[str, socket.socket] = {}

    def accept_one() -> None:
        conn, _ = listener.accept()
        conn.settimeout(1.0)
        accepted["conn"] = conn

    thread = threading.Thread(target=accept_one, daemon=True)
    thread.start()
    client = socket.create_connection(("127.0.0.1", port), timeout=3.0)
    thread.join(timeout=3.0)
    assert "conn" in accepted
    server = accepted["conn"]

    received: list[tuple[int, bytes]] = []
    got_chat = threading.Event()
    key_a = b"a" * 32
    key_b = b"b" * 32
    path_a = TcpPath(client, lambda path, message: None, lambda path, reason: None, "client")
    path_b = TcpPath(server, lambda path, message: None, lambda path, reason: None, "server")
    path_a.start()
    path_b.start()
    channel_a = TcpPathSecureChannel(
        path_a,
        key_a,
        key_b,
        on_frame=lambda frame_type, payload: None,
        on_close=lambda reason: None,
    )
    channel_b = TcpPathSecureChannel(
        path_b,
        key_b,
        key_a,
        on_frame=lambda frame_type, payload: (received.append((frame_type, payload)), got_chat.set()),
        on_close=lambda reason: None,
    )
    try:
        channel_a.start()
        time.sleep(0.3)
        channel_b.start()
        assert channel_a.wait_ready(3.0)
        assert channel_b.wait_ready(3.0)
        channel_a.send_chat("over tcp")
        assert got_chat.wait(3.0)
        assert received == [(FRAME_DATA, b"over tcp")]
    finally:
        channel_a.close()
        channel_b.close()
        path_a.close()
        path_b.close()
        listener.close()
