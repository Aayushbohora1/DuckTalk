from __future__ import annotations

import socket
import threading
import time

import pytest

import ducktalk.session as session_module
from ducktalk.candidates import Invite, new_quick_code
from ducktalk.session import (
    Callbacks,
    DirectConnectError,
    HostSession,
    JoinSession,
    SessionConfig,
)


def loopback_addresses(family: int, allow_loopback: bool = False) -> list[str]:
    if not allow_loopback:
        return []
    return ["127.0.0.1"] if family == 4 else ["::1"]


@pytest.fixture(autouse=True)
def force_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(session_module, "gather_host_addresses", loopback_addresses)


def make_config(
    name: str,
    *,
    family: int = 4,
    udp: bool = True,
    tcp: bool = False,
    port: int = 0,
    quick_code: str = "",
) -> SessionConfig:
    return SessionConfig(
        name=name,
        stun_servers=(),
        allow_loopback=True,
        enable_udp=udp,
        enable_tcp=tcp,
        families=(family,),
        connect_timeout=15.0,
        select_timeout=15.0,
        noise_timeout=10.0,
        sas_timeout=5.0,
        udp_wait=1.0,
        port=port,
        quick_code=quick_code,
    )


def wait_for(predicate, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def run_pair(
    *,
    family: int = 4,
    udp: bool = True,
    tcp: bool = False,
    join_sas: bool = True,
    host_sas: bool = True,
    verify=None,
) -> dict:
    logs: list[str] = []
    result: dict = {}

    def host_log(message: str) -> None:
        logs.append("host: " + message)

    def join_log(message: str) -> None:
        logs.append("join: " + message)

    host = HostSession(
        make_config("host", family=family, udp=udp, tcp=tcp),
        Callbacks(
            approve_incoming=lambda info: True,
            approve_sas=lambda sas, peer: host_sas,
            log=host_log,
        ),
    )
    invite = Invite.decode(host.start().encode())

    def host_worker() -> None:
        try:
            result["host_session"] = host.wait_for_request(timeout=15.0).accept()
        except BaseException as exc:
            result["host_error"] = exc
        finally:
            result["host_done"] = True

    thread = threading.Thread(target=host_worker, daemon=True)
    thread.start()
    joiner = JoinSession(
        make_config("joiner", family=family, udp=udp, tcp=tcp),
        Callbacks(
            approve_incoming=lambda info: True,
            approve_sas=lambda sas, peer: join_sas,
            log=join_log,
        ),
        invite,
    )
    try:
        try:
            result["join_session"] = joiner.connect()
        except BaseException as exc:
            result["join_error"] = exc
        thread.join(timeout=20.0)
        result["logs"] = logs
        if verify is not None and "join_session" in result and "host_session" in result:
            verify(result)
        return result
    finally:
        session = result.get("join_session")
        if session is not None:
            session.close()
        host_session = result.get("host_session")
        if host_session is not None:
            host_session.close()
        joiner.close()
        host.close()
        thread.join(timeout=2.0)


@pytest.mark.parametrize("transport", ["udp", "tcp"])
def test_loopback_session_establishes_and_chats(transport: str) -> None:
    def verify(result: dict) -> None:
        assert "join_error" not in result, result.get("join_error")
        assert "host_error" not in result, result.get("host_error")
        join_session = result["join_session"]
        host_session = result["host_session"]
        assert join_session.sas == host_session.sas
        assert join_session.transport == transport.upper()
        assert join_session.peer_name == "host"
        assert host_session.peer_name == "joiner"
        assert join_session.remote
        assert "Limitations" in " ".join(join_session.diagnostics())
        to_host: list[str] = []
        to_join: list[str] = []
        host_session.set_message_callback(to_host.append)
        join_session.set_message_callback(to_join.append)
        join_session.send("hello host")
        host_session.send("hello joiner")
        assert wait_for(lambda: len(to_host) == 1 and len(to_join) == 1, 5.0)
        assert to_host == ["hello host"]
        assert to_join == ["hello joiner"]

    run_pair(udp=transport == "udp", tcp=transport == "tcp", verify=verify)


def test_sas_rejection_aborts_before_connected() -> None:
    result = run_pair(join_sas=False)
    assert "join_error" in result
    assert isinstance(result["join_error"], DirectConnectError)
    assert "SAS verification rejected" in str(result["join_error"])
    assert "join_session" not in result
    assert "host_session" not in result


def test_tampered_peer_key_is_rejected() -> None:
    logs: list[str] = []
    result: dict = {}
    host = HostSession(
        make_config("host"),
        Callbacks(
            approve_incoming=lambda info: True,
            approve_sas=lambda sas, peer: True,
            log=logs.append,
        ),
    )
    invite = host.start()
    bad_invite = Invite(
        invite.session_id,
        invite.token,
        invite.name,
        b"\x99" * 32,
        invite.candidates,
        invite.created_at,
        invite.expires_at,
    )

    def host_worker() -> None:
        try:
            result["host_session"] = host.wait_for_request(timeout=10.0).accept()
        except BaseException as exc:
            result["host_error"] = exc

    thread = threading.Thread(target=host_worker, daemon=True)
    thread.start()
    joiner = JoinSession(
        make_config("joiner"),
        Callbacks(
            approve_incoming=lambda info: True,
            approve_sas=lambda sas, peer: True,
            log=logs.append,
        ),
        bad_invite,
    )
    try:
        with pytest.raises(DirectConnectError):
            joiner.connect()
    finally:
        joiner.close()
        host.close()
        thread.join(timeout=5.0)
    assert "host_session" not in result


def test_ipv6_udp_loopback_when_available() -> None:
    probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        probe.bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback is unavailable")
    finally:
        probe.close()
    result = run_pair(family=6)
    if "join_error" in result and isinstance(result["join_error"], OSError):
        pytest.skip(f"IPv6 unavailable: {result['join_error']}")
    assert "join_error" not in result, result.get("join_error")
    assert "host_error" not in result, result.get("host_error")
    assert result["join_session"].transport == "UDP"


def test_control_messages_are_hmac_authenticated_without_exposing_token() -> None:
    host = HostSession(make_config("host"), Callbacks(approve_incoming=lambda info: True, approve_sas=lambda sas, peer: True))
    host._init_identity()
    message = host._control_message("connect", name="alice", static="x")
    assert "token" not in message
    assert message["auth"]
    assert host._control_auth_valid(message)
    tampered = dict(message)
    tampered["name"] = "mallory"
    assert not host._control_auth_valid(tampered)
    missing = dict(message)
    missing.pop("auth")
    assert not host._control_auth_valid(missing)


@pytest.mark.parametrize("transport", ["udp", "tcp"])
def test_direct_ip_and_code_session(transport: str) -> None:
    code = new_quick_code()
    use_udp = transport == "udp"
    use_tcp = transport == "tcp"
    result: dict = {}
    host = HostSession(
        make_config("host", udp=use_udp, tcp=use_tcp, quick_code=code),
        Callbacks(
            approve_incoming=lambda info: True,
            approve_sas=lambda sas, peer: True,
            log=lambda message: None,
        ),
    )
    invite = host.start()
    candidate = next(
        candidate for candidate in invite.candidates if candidate.protocol == transport
    )
    direct = Invite.direct_for(
        candidate.address,
        candidate.port,
        code,
        include_udp=use_udp,
        include_tcp=use_tcp,
    )

    def host_worker() -> None:
        try:
            result["host_session"] = host.wait_for_request(timeout=15.0).accept()
        except BaseException as exc:
            result["host_error"] = exc

    thread = threading.Thread(target=host_worker, daemon=True)
    thread.start()
    joiner = JoinSession(
        make_config("joiner", udp=use_udp, tcp=use_tcp),
        Callbacks(
            approve_incoming=lambda info: True,
            approve_sas=lambda sas, peer: True,
            log=lambda message: None,
        ),
        direct,
    )
    try:
        result["join_session"] = joiner.connect()
        thread.join(timeout=20.0)
        assert "host_error" not in result, result.get("host_error")
        join_session = result["join_session"]
        host_session = result["host_session"]
        assert join_session.sas == host_session.sas
        assert join_session.transport == transport.upper()
        received: list[str] = []
        host_session.set_message_callback(received.append)
        join_session.send("direct hello")
        assert wait_for(lambda: received == ["direct hello"], 5.0)
    finally:
        session = result.get("join_session")
        if session is not None:
            session.close()
        session = result.get("host_session")
        if session is not None:
            session.close()
        joiner.close()
        host.close()
        thread.join(timeout=2.0)
