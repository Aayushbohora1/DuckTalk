"""Direct session orchestration: manual signalling, ICE-style checks, Noise, chat.

Design notes
------------
* No relay and no central transport is used anywhere.
* Manual invite codes carry endpoints, a session token and a static public key,
  never chat messages.
* The host selects a direct candidate pair and both sides run Noise XX over it.
* DuckTalk never reports a direct/connected session until the Noise handshake
  succeeded, encrypted HELLO was received, both users approved the SAS, and an
  encrypted CONFIRM was received from the peer.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import queue
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from .candidates import (
    MAX_CANDIDATES,
    Candidate,
    Invite,
    InviteError,
    b64d,
    b64e,
    gather_host_addresses,
    make_candidate,
    normalize_quick_code,
    peer_fingerprint,
    quick_identity,
    sanitize_name,
    sort_candidates,
)
from .checks import CheckManager, CheckTarget
from .nat import NatProfile, format_pair_report
from .noise import (
    NoiseError,
    NoiseHandshake,
    TransportKeys,
    generate_static,
    public_bytes,
)
from .paths import BasePath, TcpPath, UdpPath
from .stun import (
    DEFAULT_STUN_SERVERS,
    StunObservation,
    stun_discover_on_socket,
)
from .transport import (
    FRAME_CONFIRM,
    FRAME_DATA,
    MAGIC_CONTROL,
    MAGIC_SECURE,
    TcpPathSecureChannel,
    TransportError,
    UdpEndpoint,
    UdpSecureChannel,
    addr_key,
    tcp_connect,
)

CONTROL_TYPES = {"connect", "peer_info", "ready", "select", "reject"}


class DirectConnectError(RuntimeError):
    def __init__(self, message: str, details: list[str] | None = None) -> None:
        super().__init__(message)
        self.details = details or []


class SessionAborted(DirectConnectError):
    """A local security decision that must not be retried on another path."""


@dataclass
class SessionConfig:
    name: str
    stun_servers: tuple[str, ...] = DEFAULT_STUN_SERVERS
    allow_loopback: bool = False
    enable_udp: bool = True
    enable_tcp: bool = True
    families: tuple[int, ...] = (4, 6)
    stun_timeout: float = 1.2
    connect_timeout: float = 30.0
    select_timeout: float = 25.0
    noise_timeout: float = 15.0
    sas_timeout: float = 120.0
    udp_wait: float = 6.0
    invite_ttl: int = 3600
    debug: bool = False
    port: int = 0
    quick_code: str = ""

    def __post_init__(self) -> None:
        self.name = sanitize_name(self.name, fallback="peer")
        self.stun_servers = tuple(self.stun_servers)
        self.families = tuple(sorted(set(self.families)))
        if not 0 <= self.port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        if self.quick_code:
            self.quick_code = normalize_quick_code(self.quick_code)


@dataclass
class IncomingInfo:
    peer_name: str
    transport: str
    remote: str
    fingerprint: str
    response: bool = False
    candidate_count: int = 0
    local_name: str = ""

    def summary(self) -> str:
        if self.response:
            return (
                f"{self.peer_name} accepted your request over {self.transport.upper()} "
                f"({self.remote}). Key {self.fingerprint}."
            )
        return (
            f"{self.peer_name} is requesting a direct session over {self.transport.upper()} "
            f"from {self.remote}. Key {self.fingerprint}."
        )


@dataclass
class Callbacks:
    approve_incoming: Callable[[IncomingInfo], bool]
    approve_sas: Callable[[str, str], bool]
    log: Callable[[str], None] = print


@dataclass
class PeerDescription:
    name: str
    static_public: bytes
    candidates: list[Candidate] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        return peer_fingerprint(self.static_public)


@dataclass
class PathAttempt:
    pair: str
    protocol: str
    status: str
    detail: str = ""


def _prologue(sid: bytes, initiator_name: str, responder_name: str) -> bytes:
    return (
        b"DuckTalk/1\x00"
        + sid
        + b"\x00"
        + initiator_name.encode("utf-8", "replace")
        + b"\x00"
        + responder_name.encode("utf-8", "replace")
    )


def _parse_candidates(message: dict) -> list[Candidate]:
    raw = message.get("candidates", [])
    if not isinstance(raw, list):
        raise DirectConnectError("peer sent an invalid candidate list")
    if len(raw) > MAX_CANDIDATES:
        raise DirectConnectError("peer sent too many candidates")
    candidates: list[Candidate] = []
    ids: set[str] = set()
    for item in raw:
        try:
            candidate = Candidate.from_json(item)
        except InviteError as exc:
            raise DirectConnectError(f"peer sent an invalid candidate: {exc}") from exc
        if candidate.id in ids:
            raise DirectConnectError("peer sent duplicate candidate ids")
        ids.add(candidate.id)
        candidates.append(candidate)
    return candidates


class _SecureRuntime:
    def __init__(self, channel, path: BasePath, on_path_close: Callable[[], None]) -> None:
        self.channel = channel
        self.path = path
        self.approved = False
        self.on_message: Callable[[str], None] | None = None
        self.confirm = threading.Event()
        self.closed = threading.Event()
        self.reason = ""
        self._on_path_close = on_path_close

    def on_frame(self, frame_type: int, payload: bytes) -> None:
        if frame_type == FRAME_CONFIRM:
            self.confirm.set()
            return
        if frame_type == FRAME_DATA:
            if not self.approved or self.on_message is None:
                return
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                return
            try:
                self.on_message(text)
            except Exception:
                pass

    def on_close(self, reason: str) -> None:
        self.reason = reason
        self.closed.set()
        try:
            self._on_path_close()
        except Exception:
            pass


class SecureSession:
    """A direct session that has passed Noise authentication and SAS approval."""

    def __init__(
        self,
        owner,
        runtime: _SecureRuntime,
        *,
        peer_name: str,
        local_name: str,
        sas: str,
        transport_label: str,
        remote_label: str,
        owner_lines: Callable[[], list[str]],
    ) -> None:
        self._owner = owner
        self._runtime = runtime
        self.peer_name = peer_name
        self.local_name = local_name
        self.sas = sas
        self.transport = transport_label
        self.remote = remote_label
        self._owner_lines = owner_lines
        self.closed = False

    @property
    def is_closed(self) -> bool:
        return self.closed or self._runtime.closed.is_set()

    @property
    def close_reason(self) -> str:
        return self._runtime.reason

    def set_message_callback(self, callback: Callable[[str], None]) -> None:
        self._runtime.on_message = callback

    def send(self, text: str) -> None:
        if self.is_closed:
            raise DirectConnectError("session is closed")
        try:
            self._runtime.channel.send_chat(text)
        except TransportError as exc:
            raise DirectConnectError(f"send failed: {exc}") from exc

    def wait_closed(self, timeout: float | None = None) -> bool:
        return self._runtime.closed.wait(timeout)

    def close(self, reason: str = "closed locally") -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self._runtime.channel.close(reason)
        except Exception:
            pass
        try:
            self._owner.close()
        except Exception:
            pass

    def diagnostics(self) -> list[str]:
        return self._owner_lines()


class _BaseSession:
    def __init__(self, config: SessionConfig, callbacks: Callbacks) -> None:
        self.config = config
        self.callbacks = callbacks
        self.sid = b""
        self.token = b""
        self.static_private = generate_static()
        self.static_public = public_bytes(self.static_private)
        self.endpoints: dict[str, UdpEndpoint] = {}
        self.endpoint_ips: dict[str, str] = {}
        self.endpoint_ports: dict[str, int] = {}
        self.observations: dict[str, list[StunObservation]] = {}
        self.candidates: list[Candidate] = []
        self.tcp_listeners: list[tuple[socket.socket, int]] = []
        self.tcp_ports: dict[int, int] = {}
        self._tcp_accept_threads: list[threading.Thread] = []
        self._paths: dict[tuple, BasePath] = {}
        self._tcp_paths: list[TcpPath] = []
        self._control_queue: queue.Queue[tuple[BasePath, dict]] = queue.Queue()
        self._stash: list[tuple[BasePath, dict]] = []
        self._paths_lock = threading.Lock()
        self._checks: CheckManager | None = None
        self._closed = False
        self._close_lock = threading.Lock()
        self._active_runtime: _SecureRuntime | None = None
        self._locked_down = False
        self._last_path_report: list[PathAttempt] = []
        self._listen_tcp = False

    # ------------------------------------------------------------------ setup
    def _init_identity(self) -> None:
        import os

        if self.config.quick_code:
            self.sid, self.token = quick_identity(self.config.quick_code)
            return
        self.sid = os.urandom(16)
        self.token = os.urandom(16)

    def _setup(self, *, listen_tcp: bool, controlling: bool) -> None:
        self._listen_tcp = listen_tcp
        self._gather_udp()
        if listen_tcp:
            self._start_tcp_listeners()
        self._start_checks(controlling)
        for endpoint in self.endpoints.values():
            endpoint.start(
                lambda data, source, key=endpoint.local_key: self._on_udp(key, data, source)
            )
        for thread in self._tcp_accept_threads:
            thread.start()

    def _gather_udp(self) -> None:
        for family in self.config.families:
            if not self.config.enable_udp:
                break
            key = f"udp{family}"
            bind_ip = "0.0.0.0" if family == 4 else "::"
            try:
                endpoint = UdpEndpoint(family, bind_ip, key, port=self.config.port)
            except OSError as exc:
                if self.config.port:
                    self.callbacks.log(
                        f"Port {self.config.port} unavailable for IPv{family} UDP; using an ephemeral port"
                    )
                    try:
                        endpoint = UdpEndpoint(family, bind_ip, key)
                    except OSError as retry_exc:
                        self.callbacks.log(f"Skipping IPv{family} UDP: {retry_exc}")
                        continue
                else:
                    self.callbacks.log(f"Skipping IPv{family} UDP: {exc}")
                    continue
            self.endpoints[key] = endpoint
            self.endpoint_ports[key] = endpoint.local_port
            addresses = gather_host_addresses(family, self.config.allow_loopback)
            if addresses:
                self.endpoint_ips[key] = addresses[0]
            for index, address in enumerate(addresses, 1):
                cid = f"u{family}h" if index == 1 else f"u{family}h{index}"
                self.candidates.append(
                    make_candidate(
                        cid=cid,
                        protocol="udp",
                        kind="host",
                        address=address,
                        port=endpoint.local_port,
                        local_key=key,
                    )
                )
            observations: list[StunObservation] = []
            if self.config.stun_servers:
                for server in self.config.stun_servers:
                    observation = stun_discover_on_socket(
                        endpoint.sock, server, family=family, timeout=self.config.stun_timeout
                    )
                    observations.append(observation)
                try:
                    endpoint.sock.settimeout(0.2)
                except OSError:
                    pass
                seen: set[tuple[str, int]] = set()
                srflx_index = 0
                for observation in observations:
                    if not observation.ok or observation.mapped is None:
                        continue
                    if observation.mapped in seen:
                        continue
                    seen.add(observation.mapped)
                    srflx_index += 1
                    mapped_ip, mapped_port = observation.mapped
                    try:
                        self.candidates.append(
                            make_candidate(
                                cid=f"u{family}s{srflx_index}",
                                protocol="udp",
                                kind="srflx",
                                address=mapped_ip,
                                port=mapped_port,
                                local_key=key,
                            )
                        )
                    except ValueError:
                        continue
            self.observations[key] = observations

    def _start_tcp_listeners(self) -> None:
        if not self.config.enable_tcp:
            return
        bound: list[tuple[socket.socket, int]] = []
        for family in self.config.families:
            af = socket.AF_INET if family == 4 else socket.AF_INET6
            bind_ip = "0.0.0.0" if family == 4 else "::"
            sock: socket.socket | None = None
            requested_port = self.endpoint_ports.get(f"udp{family}", self.config.port)
            try:
                sock = socket.socket(af, socket.SOCK_STREAM)
                try:
                    sock.bind((bind_ip, requested_port))
                except OSError:
                    if not requested_port:
                        raise
                    self.callbacks.log(
                        f"Port {requested_port} unavailable for IPv{family} TCP; using an ephemeral port"
                    )
                    sock.bind((bind_ip, 0))
                sock.listen(16)
                sock.settimeout(0.5)
                port = int(sock.getsockname()[1])
                self.tcp_ports[family] = port
                bound.append((sock, family))
                addresses = gather_host_addresses(family, self.config.allow_loopback)
                for index, address in enumerate(addresses, start=1):
                    cid = f"t{family}h" if index == 1 else f"t{family}h{index}"
                    self.candidates.append(
                        make_candidate(
                            cid=cid,
                            protocol="tcp",
                            kind="host",
                            address=address,
                            port=port,
                            local_key=f"tcp{family}",
                        )
                    )
            except OSError as exc:
                if sock is not None:
                    sock.close()
                self.callbacks.log(f"Skipping IPv{family} TCP listener: {exc}")
        self.tcp_listeners.extend(bound)
        for sock, family in bound:
            thread = threading.Thread(
                target=self._accept_loop,
                args=(sock, family),
                name=f"tcp-accept-{family}",
                daemon=True,
            )
            self._tcp_accept_threads.append(thread)

    def _accept_loop(self, sock: socket.socket, family: int) -> None:
        while not self._closed:
            try:
                conn, _source = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            if self._closed or self._locked_down:
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            try:
                path = TcpPath(
                    conn,
                    self._on_path_control,
                    self._on_path_close,
                    description=f"TCP/{ 'IPv4' if family == 4 else 'IPv6'}",
                )
                with self._paths_lock:
                    self._tcp_paths.append(path)
                    if len(self._tcp_paths) > 32:
                        old = self._tcp_paths.pop(0)
                        old.close("too many TCP paths")
                path.start()
            except OSError:
                try:
                    conn.close()
                except OSError:
                    pass
        # leave listener cleanup to close()

    def _start_checks(self, controlling: bool) -> None:
        local_ids: dict[str, str] = {}
        for key in self.endpoints:
            for candidate in self.candidates:
                if candidate.protocol == "udp" and candidate.local_key == key:
                    local_ids[key] = candidate.id
                    break
        self._checks = CheckManager(
            self.endpoints,
            local_ids,
            username=f"ducktalk:{self.sid.hex()}",
            password=self.token,
            controlling=controlling,
            tiebreaker=int.from_bytes(self.sid[:8], "big"),
            debug=self.config.debug,
        )
        self._checks.start()

    # --------------------------------------------------------------- networking
    def _on_udp(self, local_key: str, data: bytes, source: tuple) -> None:
        endpoint = self.endpoints.get(local_key)
        if endpoint is None:
            return
        if (
            len(data) >= 20
            and data[4:8] == b"\x21\x12\xa4\x42"
            and (data[0] & 0xC0) == 0
            and self._checks is not None
            and self._checks.handle(data, source, endpoint)
        ):
            return
        if data.startswith(MAGIC_CONTROL):
            if len(data) < 8:
                return
            length = int.from_bytes(data[4:8], "big")
            if length > 16384 or len(data) < 8 + length:
                return
            raw = data[8 : 8 + length]
            path = self._get_or_create_udp_path(local_key, source)
            if path is None:
                return
            path.handle_control_payload(raw)
            return
        if data.startswith(MAGIC_SECURE):
            path = self._lookup_udp_path(local_key, source)
            if path is not None:
                path.push_secure(data)

    def _get_or_create_udp_path(self, local_key: str, remote: tuple) -> UdpPath | None:
        endpoint = self.endpoints.get(local_key)
        if endpoint is None:
            return None
        remote = addr_key(remote)
        key = (local_key, remote[0], remote[1])
        with self._paths_lock:
            existing = self._paths.get(key)
            if isinstance(existing, UdpPath):
                return existing
            if len(self._paths) > 128:
                return None
            path = UdpPath(endpoint, remote, self._on_path_control, self._on_path_close)
            self._paths[key] = path
            return path

    def _lookup_udp_path(self, local_key: str, remote: tuple) -> UdpPath | None:
        remote = addr_key(remote)
        key = (local_key, remote[0], remote[1])
        with self._paths_lock:
            path = self._paths.get(key)
        return path if isinstance(path, UdpPath) else None

    def _on_path_control(self, path: BasePath, message: dict) -> None:
        if self._closed:
            path.close("closing")
            return
        if message.get("v") != 1:
            return
        msg_type = message.get("type")
        if msg_type not in CONTROL_TYPES:
            return
        try:
            if b64d(str(message.get("sid", ""))) != self.sid:
                return
            if not self._control_auth_valid(message):
                return
        except Exception:
            return
        self._control_queue.put((path, message))

    def _on_path_close(self, path: BasePath, reason: str) -> None:
        runtime = self._active_runtime
        if runtime is not None and runtime.path is path:
            fail = getattr(runtime.channel, "fail", None)
            if callable(fail):
                fail(reason)
        if self.config.debug:
            self.callbacks.log(f"[debug] path closed: {path.describe()} ({reason})")

    def _control_auth_valid(self, message: dict) -> bool:
        auth_text = message.get("auth")
        if not isinstance(auth_text, str):
            return False
        try:
            supplied = b64d(auth_text)
        except InviteError:
            return False
        payload = {key: value for key, value in message.items() if key != "auth"}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(self.token, canonical, hashlib.sha256).digest()
        return hmac.compare_digest(supplied, expected)

    def _control_message(self, msg_type: str, **fields) -> dict:
        message = {"v": 1, "type": msg_type, "sid": b64e(self.sid)}
        message.update(fields)
        canonical = json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")
        message["auth"] = b64e(hmac.new(self.token, canonical, hashlib.sha256).digest())
        return message

    def _send_control(self, path: BasePath, msg_type: str, **fields) -> None:
        path.send_control(self._control_message(msg_type, **fields))

    def _wait_control(
        self,
        types: set[str],
        *,
        path: BasePath | None = None,
        timeout: float,
        failure: str,
    ) -> tuple[BasePath, dict]:
        deadline = time.monotonic() + timeout
        while True:
            if self._closed:
                raise DirectConnectError("session closed while waiting", self.diagnostics())
            for index, (candidate_path, message) in enumerate(self._stash):
                if message.get("type") in types and (path is None or candidate_path is path):
                    self._stash.pop(index)
                    return candidate_path, message
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DirectConnectError(failure, self.diagnostics())
            try:
                candidate_path, message = self._control_queue.get(timeout=min(0.2, remaining))
            except queue.Empty:
                continue
            if candidate_path.closed and path is not None and candidate_path is path:
                raise DirectConnectError(f"path closed: {candidate_path.close_reason}", self.diagnostics())
            if message.get("type") in types and (path is None or candidate_path is path):
                return candidate_path, message
            self._stash.append((candidate_path, message))
            if len(self._stash) > 100:
                self._stash.pop(0)

    def _wait_noise(self, path: BasePath, timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.closed:
                raise DirectConnectError(f"path closed: {path.close_reason}")
            item = path.next_noise(min(0.2, max(0.01, deadline - time.monotonic())))
            if item is not None:
                return item
        raise DirectConnectError("timed out waiting for Noise handshake data")

    # --------------------------------------------------------------- lifecycle
    def _stop_checks(self) -> None:
        if self._checks is not None:
            self._checks.stop()
            self._checks = None

    def _close_listeners(self) -> None:
        for sock, _ in self.tcp_listeners:
            try:
                sock.close()
            except OSError:
                pass
        self.tcp_listeners = []

    def lock_down(self, selected: BasePath) -> None:
        if self._locked_down:
            return
        self._locked_down = True
        self._stop_checks()
        self._close_listeners()
        with self._paths_lock:
            paths = list(self._paths.values()) + list(self._tcp_paths)
        for path in paths:
            if path is selected:
                continue
            path.close("session selected another path")
        for endpoint_key, endpoint in list(self.endpoints.items()):
            if isinstance(selected, UdpPath) and endpoint_key == selected.endpoint.local_key:
                continue
            endpoint.close()
            self.endpoints.pop(endpoint_key, None)

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
            self._stop_checks()
            self._close_listeners()
            with self._paths_lock:
                paths = list(self._paths.values()) + list(self._tcp_paths)
            for path in paths:
                path.close("session closed")
            for endpoint in list(self.endpoints.values()):
                endpoint.close()
            self.endpoints.clear()

    def diagnostics(self) -> list[str]:
        lines: list[str] = []
        if hasattr(self, "_nat_profile"):
            lines.extend(self._nat_profile.as_lines())
        lines.append("Candidate pairs:")
        if self._checks is not None:
            lines.extend(format_pair_report(self._checks.report_rows()))
        else:
            lines.extend(format_pair_report([]))
        if self._last_path_report:
            lines.append("Selected-path attempts:")
            for attempt in self._last_path_report:
                lines.append(f"  {attempt.protocol.upper():3} {attempt.status:12} {attempt.pair} {attempt.detail}".rstrip())
        return lines

    # --------------------------------------------------------------- finalize
    def _secure_channel_for(self, path: BasePath, keys: TransportKeys, runtime: _SecureRuntime):
        if isinstance(path, UdpPath):
            channel = UdpSecureChannel(
                path.endpoint,
                path.remote,
                keys.send,
                keys.receive,
                on_frame=runtime.on_frame,
                on_close=runtime.on_close,
            )
            path.attach_secure(lambda data: channel.receive(data, path.remote))
            return channel
        if isinstance(path, TcpPath):
            channel = TcpPathSecureChannel(
                path,
                keys.send,
                keys.receive,
                on_frame=runtime.on_frame,
                on_close=runtime.on_close,
            )
            return channel
        raise DirectConnectError("unsupported path type")

    def _confirm_secure(
        self,
        path: BasePath,
        handshake: NoiseHandshake,
        *,
        peer_name: str,
        local_name: str,
        expected_peer_static: bytes,
    ) -> SecureSession:
        if handshake.remote_static is None or not hmac.compare_digest(
            handshake.remote_static, expected_peer_static
        ):
            raise DirectConnectError(
                "Noise authenticated a different peer key than the one signalled"
            )
        keys = handshake.split()
        sas = handshake.sas_code()
        channel_holder: dict[str, object] = {}

        def close_runtime(reason: str) -> None:
            channel = channel_holder.get("channel")
            if channel is not None and hasattr(channel, "fail"):
                channel.fail(reason)

        runtime = _SecureRuntime(None, path, lambda: None)  # type: ignore[arg-type]
        channel = self._secure_channel_for(path, keys, runtime)
        runtime.channel = channel
        channel_holder["channel"] = channel
        self._active_runtime = runtime
        runtime.closed.clear()
        channel.start()
        if not channel.wait_ready(self.config.noise_timeout):
            if runtime.closed.is_set():
                raise DirectConnectError(f"secure channel closed: {runtime.reason}", self.diagnostics())
            channel.close("HELLO not received")
            raise DirectConnectError("peer did not confirm the encrypted channel", self.diagnostics())
        if not self.callbacks.approve_sas(sas, peer_name):
            channel.close("SAS rejected locally")
            raise SessionAborted("SAS verification rejected; session aborted", self.diagnostics())
        try:
            channel.send_frame(FRAME_CONFIRM, b"")
        except TransportError as exc:
            raise DirectConnectError(f"could not send SAS confirmation: {exc}", self.diagnostics()) from exc
        deadline = time.monotonic() + self.config.sas_timeout
        while not runtime.confirm.is_set():
            if runtime.closed.is_set():
                raise DirectConnectError(
                    f"peer did not confirm the SAS ({runtime.reason})", self.diagnostics()
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                channel.close("SAS confirmation timed out")
                raise DirectConnectError("timed out waiting for mutual SAS confirmation", self.diagnostics())
            runtime.confirm.wait(min(0.2, remaining))
        runtime.approved = True
        self.lock_down(path)
        transport_label = "UDP" if isinstance(path, UdpPath) else "TCP"
        remote = f"{path.remote[0]}:{path.remote[1]}" if isinstance(path, UdpPath) else path.describe()
        session = SecureSession(
            self,
            runtime,
            peer_name=peer_name,
            local_name=local_name,
            sas=sas,
            transport_label=transport_label,
            remote_label=remote,
            owner_lines=self.diagnostics,
        )
        return session

    # --------------------------------------------------------------- handshake
    def _responder_handshake(
        self,
        path: BasePath,
        first_message: bytes,
        *,
        peer_name: str,
        local_name: str,
        initiator_name: str,
        expected_peer_static: bytes,
    ) -> SecureSession:
        handshake = NoiseHandshake(
            False, self.static_private, _prologue(self.sid, initiator_name, local_name)
        )
        msg1 = first_message
        try:
            payload = handshake.read_message(msg1)
        except NoiseError as exc:
            raise DirectConnectError(f"Noise handshake rejected: {exc}") from exc
        if payload:
            raise DirectConnectError("unexpected Noise payload")
        msg2 = handshake.write_message(b"")
        path.send_noise(msg2)
        deadline = time.monotonic() + self.config.noise_timeout
        next_resend = time.monotonic() + 0.6
        while not handshake.is_finished:
            if path.closed:
                raise DirectConnectError(f"path closed during handshake: {path.close_reason}")
            if time.monotonic() > deadline:
                raise DirectConnectError("Noise handshake timed out")
            if time.monotonic() >= next_resend:
                try:
                    path.send_noise(msg2)
                except Exception:
                    pass
                next_resend = time.monotonic() + 0.6
            try:
                data = path.next_noise(0.15)
            except Exception:
                data = None
            if data is None:
                continue
            if data == msg1:
                try:
                    path.send_noise(msg2)
                except Exception:
                    pass
                continue
            try:
                handshake.read_message(data)
            except NoiseError as exc:
                raise DirectConnectError(f"Noise handshake failed: {exc}") from exc
        return self._confirm_secure(
            path,
            handshake,
            peer_name=peer_name,
            local_name=local_name,
            expected_peer_static=expected_peer_static,
        )

    def _initiator_handshake(
        self,
        path: BasePath,
        *,
        peer_name: str,
        local_name: str,
        expected_peer_static: bytes,
    ) -> SecureSession:
        handshake = NoiseHandshake(
            True, self.static_private, _prologue(self.sid, local_name, peer_name)
        )
        msg1 = handshake.write_message(b"")
        path.send_noise(msg1)
        deadline = time.monotonic() + self.config.noise_timeout
        next_resend = time.monotonic() + 0.6
        got_msg2 = False
        while not got_msg2:
            if path.closed:
                raise DirectConnectError(f"path closed during handshake: {path.close_reason}")
            if time.monotonic() > deadline:
                raise DirectConnectError("Noise handshake timed out")
            if time.monotonic() >= next_resend:
                try:
                    path.send_noise(msg1)
                except Exception:
                    pass
                next_resend = time.monotonic() + 0.6
            data = path.next_noise(0.15)
            if data is None:
                continue
            try:
                handshake.read_message(data)
                got_msg2 = True
            except NoiseError as exc:
                raise DirectConnectError(f"Noise handshake failed: {exc}") from exc
        msg3 = handshake.write_message(b"")
        path.send_noise(msg3)
        for _ in range(3):
            threading.Timer(0.5, self._safe_send_noise, args=(path, msg3)).start()
        return self._confirm_secure(
            path,
            handshake,
            peer_name=peer_name,
            local_name=local_name,
            expected_peer_static=expected_peer_static,
        )

    @staticmethod
    def _safe_send_noise(path: BasePath, data: bytes) -> None:
        try:
            if not path.closed:
                path.send_noise(data)
        except Exception:
            pass


class HostSession(_BaseSession):
    def __init__(self, config: SessionConfig, callbacks: Callbacks) -> None:
        super().__init__(config, callbacks)
        self._invite: Invite | None = None
        self._seen_peers: set[bytes] = set()
        self._nat_profile: NatProfile | None = None

    def start(self) -> Invite:
        self._init_identity()
        self._setup(listen_tcp=True, controlling=True)
        now = int(time.time())
        self._nat_profile = NatProfile.from_sockets(
            [
                (4 if key == "udp4" else 6, self.endpoint_ips.get(key), endpoint.local_port, obs)
                for key, endpoint in self.endpoints.items()
                for obs in [self.observations.get(key, [])]
            ],
            self.config.stun_servers,
        )
        self._invite = Invite(
            self.sid,
            self.token,
            self.config.name,
            self.static_public,
            sort_candidates(self.candidates),
            now,
            now + self.config.invite_ttl,
        )
        self.callbacks.log(f"NAT assessment: {self._nat_profile.summary()}")
        return self._invite

    @property
    def invite(self) -> Invite:
        if self._invite is None:
            raise DirectConnectError("host session has not been started")
        return self._invite

    @property
    def nat_profile(self) -> NatProfile | None:
        return self._nat_profile

    def local_endpoints(self) -> list[tuple[str, str, int]]:
        seen: set[tuple[str, str, int]] = set()
        result: list[tuple[str, str, int]] = []
        for candidate in self.candidates:
            if candidate.kind != "host":
                continue
            item = (candidate.protocol, candidate.address, candidate.port)
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result

    def public_endpoints(self) -> list[tuple[str, str, int]]:
        seen: set[tuple[str, str, int]] = set()
        result: list[tuple[str, str, int]] = []
        for candidate in self.candidates:
            if candidate.kind != "srflx":
                continue
            item = (candidate.protocol, candidate.address, candidate.port)
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result

    def wait_for_request(self, timeout: float | None = None) -> IncomingRequest:
        timeout = self.config.connect_timeout * 10 if timeout is None else timeout
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DirectConnectError("no incoming request before the timeout", self.diagnostics())
            try:
                path, message = self._wait_control(
                    {"connect"},
                    timeout=min(remaining, 1.0),
                    failure="no incoming request yet",
                )
            except DirectConnectError:
                if self._closed:
                    raise
                continue
            try:
                static = b64d(str(message.get("static", "")))
                name = sanitize_name(str(message.get("name", "peer")))
                candidates = _parse_candidates(message)
            except Exception:
                continue
            if len(static) != 32 or static in self._seen_peers:
                continue
            self._seen_peers.add(static)
            transport = "udp" if isinstance(path, UdpPath) else "tcp"
            remote = (
                f"{path.remote[0]}:{path.remote[1]}" if isinstance(path, UdpPath) else path.describe()
            )
            info = IncomingInfo(
                peer_name=name,
                transport=transport,
                remote=remote,
                fingerprint=peer_fingerprint(static),
                response=False,
                candidate_count=len(candidates),
                local_name=self.config.name,
            )
            if not self.callbacks.approve_incoming(info):
                try:
                    self._send_control(path, "reject", reason="rejected by host")
                except Exception:
                    pass
                self._seen_peers.discard(static)
                continue
            return IncomingRequest(self, path, message, name, static, candidates)


class IncomingRequest:
    def __init__(
        self,
        host: HostSession,
        path: BasePath,
        message: dict,
        peer_name: str,
        peer_static: bytes,
        candidates: list[Candidate],
    ) -> None:
        self.host = host
        self.path = path
        self.message = message
        self.peer_name = peer_name
        self.peer_static = peer_static
        self.candidates = candidates

    def reject(self, reason: str = "rejected by host") -> None:
        try:
            self.host._send_control(self.path, "reject", reason=reason)
        except Exception:
            pass

    def _add_check_targets(self) -> None:
        checks = self.host._checks
        if checks is None:
            return
        for candidate in self.candidates:
            if candidate.protocol == "udp":
                checks.add_candidate(candidate)
        if isinstance(self.path, UdpPath):
            checks.add_reflexive(
                self.path.remote[0],
                self.path.remote[1],
                self.path.endpoint.local_key,
                remote_id="observed-peer",
            )

    def accept(self) -> SecureSession:
        host = self.host
        if self.path.closed:
            raise DirectConnectError("request path closed before acceptance", host.diagnostics())
        try:
            host._send_control(
                self.path,
                "peer_info",
                name=host.config.name,
                static=b64e(host.static_public),
                candidates=[c.to_json() for c in sort_candidates(host.candidates)],
                accepted=True,
            )
        except Exception as exc:
            raise DirectConnectError(f"could not send peer_info: {exc}", host.diagnostics()) from exc
        self._add_check_targets()
        ready_path, ready_message = host._wait_control(
            {"ready", "reject"},
            path=self.path,
            timeout=host.config.connect_timeout * 4,
            failure="peer did not confirm the request",
        )
        if ready_message.get("type") == "reject":
            raise DirectConnectError(
                f"peer rejected the session ({ready_message.get('reason', 'no reason')})",
                host.diagnostics(),
            )
        if ready_path is not self.path:
            raise DirectConnectError("READY arrived on an unexpected path")
        # Wait for at least one successful UDP check and a short settle window.
        checks = host._checks
        successes: list[CheckTarget] = []
        settle_deadline = time.monotonic() + host.config.udp_wait
        success_seen_at: float | None = None
        while time.monotonic() < settle_deadline:
            if checks is not None:
                successes = checks.successful()
                if successes and success_seen_at is None:
                    success_seen_at = time.monotonic()
                if success_seen_at is not None and time.monotonic() - success_seen_at >= 0.5:
                    break
            if self.path.closed:
                break
            time.sleep(0.1)

        for target in sorted(successes, key=lambda t: (-t.priority, t.rtt_ms or 1e9)):
            if checks is not None and not checks.inbound_from(target.local_key, target.remote):
                # Outgoing success is enough for our simplified ICE subset, but
                # record whether the peer also punched toward this endpoint.
                pass
            path = host._get_or_create_udp_path(target.local_key, target.remote)
            if path is None:
                continue
            try:
                first_noise = self._select_udp(path, target)
                attempt = self.host._responder_handshake(
                    path,
                    first_noise,
                    peer_name=self.peer_name,
                    local_name=host.config.name,
                    initiator_name=self.peer_name,
                    expected_peer_static=self.peer_static,
                )
                host._last_path_report.append(
                    PathAttempt(f"{target.local_key}->{target.address}:{target.port}", "udp", "secured", "Noise XX + SAS")
                )
                return attempt
            except SessionAborted:
                raise
            except DirectConnectError as exc:
                host._last_path_report.append(
                    PathAttempt(f"{target.local_key}->{target.address}:{target.port}", "udp", "failed", str(exc))
                )
                continue

        with host._paths_lock:
            tcp_paths = [path for path in host._tcp_paths if not path.closed]
        for tcp_path in tcp_paths:
            try:
                host._send_control(tcp_path, "select", proto="tcp")
                first_noise = host._wait_noise(tcp_path, host.config.noise_timeout)
                attempt = host._responder_handshake(
                    tcp_path,
                    first_noise,
                    peer_name=self.peer_name,
                    local_name=host.config.name,
                    initiator_name=self.peer_name,
                    expected_peer_static=self.peer_static,
                )
                host._last_path_report.append(
                    PathAttempt(tcp_path.describe(), "tcp", "secured", "Noise XX + SAS")
                )
                return attempt
            except SessionAborted:
                raise
            except DirectConnectError as exc:
                host._last_path_report.append(
                    PathAttempt(tcp_path.describe(), "tcp", "failed", str(exc))
                )
        details = host.diagnostics()
        details.append("No viable direct candidate pair completed an authenticated session.")
        raise DirectConnectError(
            "could not establish a direct encrypted path; no relay fallback exists", details
        )

    def _select_udp(self, path: UdpPath, target: CheckTarget) -> bytes:
        host = self.host
        deadline = time.monotonic() + 6.0
        next_select = 0.0
        while time.monotonic() < deadline:
            if path.closed:
                raise DirectConnectError(f"UDP path closed: {path.close_reason}")
            now = time.monotonic()
            if now >= next_select:
                try:
                    host._send_control(path, "select", proto="udp", pair=target.remote_id)
                except Exception as exc:
                    raise DirectConnectError(f"could not send SELECT: {exc}") from exc
                next_select = now + 0.8
            item = path.next_noise(0.15)
            if item is not None:
                return item
        raise DirectConnectError("peer did not start the Noise handshake after SELECT")


class JoinSession(_BaseSession):
    def __init__(self, config: SessionConfig, callbacks: Callbacks, invite: Invite) -> None:
        super().__init__(config, callbacks)
        self.invite = invite
        self.sid = invite.session_id
        self.token = invite.token
        self.static_private = generate_static()
        self.static_public = public_bytes(self.static_private)
        self._peer: PeerDescription | None = None
        self._uri_context = (time.time(), invite.name)
        self._nat_profile: NatProfile | None = None
        self._stop_burst = threading.Event()
        self._tcp_threads: list[threading.Thread] = []

    def _check_invite(self) -> None:
        if int(time.time()) >= self.invite.expires_at:
            raise DirectConnectError("invite has expired")
        if self.invite.static_public == self.static_public:
            raise DirectConnectError("invite uses this process's key; refusing a self-session")

    def connect(self) -> SecureSession:
        self._check_invite()
        self._setup(listen_tcp=False, controlling=False)
        self._nat_profile = NatProfile.from_sockets(
            [
                (4 if key == "udp4" else 6, self.endpoint_ips.get(key), endpoint.local_port, obs)
                for key, endpoint in self.endpoints.items()
                for obs in [self.observations.get(key, [])]
            ],
            self.config.stun_servers,
        )
        self.callbacks.log(f"NAT assessment: {self._nat_profile.summary()}")
        self._create_connect_paths()
        self._prime_checks()
        self._start_connect_burst()
        try:
            peer_path, message = self._wait_control(
                {"peer_info", "reject"},
                timeout=self.config.connect_timeout,
                failure="host did not answer the manual request",
            )
            if message.get("type") == "reject":
                raise DirectConnectError(
                    f"host rejected the request ({message.get('reason', 'no reason')})",
                    self.diagnostics(),
                )
            peer = self._validate_peer_info(message)
            transport = "udp" if isinstance(peer_path, UdpPath) else "tcp"
            remote = (
                f"{peer_path.remote[0]}:{peer_path.remote[1]}"
                if isinstance(peer_path, UdpPath)
                else peer_path.describe()
            )
            info = IncomingInfo(
                peer_name=peer.name,
                transport=transport,
                remote=remote,
                fingerprint=peer.fingerprint,
                response=True,
                candidate_count=len(peer.candidates),
                local_name=self.config.name,
            )
            if not self.callbacks.approve_incoming(info):
                try:
                    self._send_control(peer_path, "reject", reason="rejected by joiner")
                except Exception:
                    pass
                raise DirectConnectError("request rejected locally")
            self._send_control(peer_path, "ready")
            self._stop_burst.set()
            return self._await_select_and_handshake(peer_path, peer)
        except Exception:
            self.close()
            raise

    def _prime_checks(self) -> None:
        if self._checks is None:
            return
        for candidate in self.invite.candidates:
            if candidate.protocol == "udp":
                self._checks.add_candidate(candidate)

    def _add_peer_checks(self, peer: PeerDescription) -> None:
        if self._checks is None:
            return
        for candidate in peer.candidates:
            if candidate.protocol == "udp":
                self._checks.add_candidate(candidate, prefix="host-")

    def _validate_peer_info(self, message: dict) -> PeerDescription:
        try:
            name = sanitize_name(str(message.get("name", "peer")))
            static = b64d(str(message.get("static", "")))
            candidates = _parse_candidates(message)
        except Exception as exc:
            raise DirectConnectError(f"invalid peer_info: {exc}") from exc
        if len(static) != 32:
            raise DirectConnectError("peer_info has an invalid static key")
        if not self.invite.direct:
            if not hmac.compare_digest(static, self.invite.static_public):
                raise DirectConnectError("peer static key does not match the invite")
            if name != self.invite.name:
                raise DirectConnectError("peer name does not match the invite")
        return PeerDescription(name, static, candidates)

    def _create_connect_paths(self) -> None:
        for candidate in sort_candidates(self.invite.candidates):
            if candidate.protocol != "udp":
                continue
            endpoint = self.endpoints.get(f"udp{candidate.family}")
            if endpoint is None:
                continue
            path = self._get_or_create_udp_path(endpoint.local_key, candidate.endpoint)
            if path is not None and self._checks is not None:
                self._checks.add_candidate(candidate)
        if self.config.enable_tcp:
            for candidate in sort_candidates(self.invite.candidates):
                if candidate.protocol == "tcp":
                    thread = threading.Thread(
                        target=self._dial_tcp,
                        args=(candidate,),
                        name=f"tcp-dial-{candidate.address}",
                        daemon=True,
                    )
                    self._tcp_threads.append(thread)
                    thread.start()

    def _connect_fields(self) -> dict:
        return {
            "name": self.config.name,
            "static": b64e(self.static_public),
            "candidates": [
                c.to_json()
                for c in sort_candidates(c for c in self.candidates if c.protocol == "udp")
            ],
        }

    def _start_connect_burst(self) -> None:
        message = self._control_message("connect", **self._connect_fields())

        def burst() -> None:
            deadline = time.monotonic() + self.config.connect_timeout
            while time.monotonic() < deadline and not self._stop_burst.is_set():
                with self._paths_lock:
                    udp_paths = [p for p in self._paths.values() if isinstance(p, UdpPath)]
                for path in udp_paths:
                    try:
                        path.send_control(message)
                    except Exception:
                        continue
                if self._stop_burst.wait(0.5):
                    return

        thread = threading.Thread(target=burst, name="connect-burst", daemon=True)
        thread.start()
        self._tcp_threads.append(thread)

    def _dial_tcp(self, candidate: Candidate) -> None:
        for attempt in range(3):
            if self._stop_burst.is_set() or self._closed:
                return
            try:
                sock = tcp_connect(candidate.address, candidate.port, timeout=2.0)
            except OSError:
                time.sleep(0.5)
                continue
            if self._closed:
                sock.close()
                return
            path = TcpPath(
                sock,
                self._on_path_control,
                self._on_path_close,
                description="TCP-out",
            )
            with self._paths_lock:
                self._tcp_paths.append(path)
            path.start()
            try:
                self._send_control(path, "connect", **self._connect_fields())
            except Exception:
                path.close("connect send failed")
                return
            return

    def _await_select_and_handshake(self, peer_path: BasePath, peer: PeerDescription) -> SecureSession:
        deadline = time.monotonic() + self.config.select_timeout
        tried: set[tuple[str, str]] = set()
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            path, message = self._wait_control(
                {"select", "reject"},
                timeout=max(0.1, remaining),
                failure="host did not select a candidate pair",
            )
            if message.get("type") == "reject":
                raise DirectConnectError(
                    f"host rejected the session ({message.get('reason', 'no reason')})",
                    self.diagnostics(),
                )
            proto = str(message.get("proto", ""))
            if proto not in ("udp", "tcp"):
                continue
            if (proto == "udp" and not isinstance(path, UdpPath)) or (
                proto == "tcp" and not isinstance(path, TcpPath)
            ):
                continue
            marker = (proto, path.describe())
            if marker in tried:
                continue
            tried.add(marker)
            try:
                expected_static = peer.static_public if self.invite.direct else self.invite.static_public
                return self._initiator_handshake(
                    path,
                    peer_name=peer.name,
                    local_name=self.config.name,
                    expected_peer_static=expected_static,
                )
            except SessionAborted:
                raise
            except DirectConnectError as exc:
                self._last_path_report.append(PathAttempt(path.describe(), proto, "failed", str(exc)))
                continue
        raise DirectConnectError("no selected candidate pair completed authentication", self.diagnostics())

    def close(self) -> None:
        self._stop_burst.set()
        super().close()
