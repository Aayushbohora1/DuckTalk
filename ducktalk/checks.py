"""ICE-style STUN connectivity checks over UDP candidate pairs.

The host (controller) sends checks to peer candidates and observed source
endpoints, then selects a pair after a successful bidirectional exchange.
This is a deliberately small subset of RFC 8445, not a full ICE agent.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from .candidates import Candidate, candidate_priority
from .stun import (
    ATTR_FINGERPRINT,
    ATTR_USERNAME,
    BINDING_ERROR,
    BINDING_REQUEST,
    BINDING_SUCCESS,
    StunError,
    build_binding_request,
    build_binding_success,
    has_valid_fingerprint,
    message_integrity_valid,
    parse_address_from_response,
    parse_message,
)
from .transport import UdpEndpoint, addr_key

CHECK_INTERVAL = 0.5
CHECK_DEADLINE = 8.0


@dataclass
class CheckTarget:
    key: tuple[str, str]
    local_key: str
    local_id: str
    remote_id: str
    address: str
    port: int
    family: int
    priority: int
    status: str = "waiting"
    attempts: int = 0
    rtt_ms: float | None = None
    mapped: tuple[str, int] | None = None
    error: str = ""
    next_send: float = 0.0
    started: float = 0.0
    finished: float = 0.0

    @property
    def remote(self) -> tuple[str, int]:
        return self.address, self.port


class CheckManager:
    def __init__(
        self,
        endpoints: dict[str, UdpEndpoint],
        local_candidate_ids: dict[str, str],
        username: str,
        password: bytes,
        *,
        controlling: bool,
        tiebreaker: int,
        debug: bool = False,
    ) -> None:
        self.endpoints = endpoints
        self.local_candidate_ids = local_candidate_ids
        self.username = username
        self.password = password
        self.controlling = controlling
        self.tiebreaker = tiebreaker
        self.debug = debug
        self._targets: dict[tuple[str, str], CheckTarget] = {}
        self._pending: dict[bytes, tuple[tuple[str, str], float]] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._inbound_keys: set[tuple[str, tuple[str, int]]] = set()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="ice-checks", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def _local_endpoint_for_family(self, family: int) -> UdpEndpoint | None:
        key = f"udp{family}"
        return self.endpoints.get(key)

    def add_candidate(self, candidate: Candidate, *, prefix: str = "") -> None:
        if candidate.protocol != "udp":
            return
        endpoint = self._local_endpoint_for_family(candidate.family)
        if endpoint is None:
            return
        local_id = self.local_candidate_ids.get(endpoint.local_key, endpoint.local_key)
        remote_id = f"{prefix}{candidate.id}" if prefix else candidate.id
        key = (endpoint.local_key, remote_id)
        with self._lock:
            if key in self._targets:
                return
            self._targets[key] = CheckTarget(
                key=key,
                local_key=endpoint.local_key,
                local_id=local_id,
                remote_id=remote_id,
                address=candidate.address,
                port=candidate.port,
                family=candidate.family,
                priority=candidate.priority,
                next_send=0.0,
                started=time.monotonic(),
            )

    def add_reflexive(self, address: str, port: int, local_key: str, remote_id: str = "peer-reflexive") -> None:
        endpoint = self.endpoints.get(local_key)
        if endpoint is None:
            return
        family = 4 if endpoint.family == 4 else 6
        local_id = self.local_candidate_ids.get(local_key, local_key)
        key = (local_key, remote_id)
        with self._lock:
            if key in self._targets:
                return
            self._targets[key] = CheckTarget(
                key=key,
                local_key=local_key,
                local_id=local_id,
                remote_id=remote_id,
                address=address,
                port=port,
                family=family,
                priority=candidate_priority("prflx", family, address),
                next_send=0.0,
                started=time.monotonic(),
            )

    def _send_check(self, target: CheckTarget) -> None:
        endpoint = self.endpoints.get(target.local_key)
        if endpoint is None:
            return
        request, txid = build_binding_request(
            username=self.username,
            password=self.password,
            priority=max(1, target.priority),
            controlling=self.controlling,
            tiebreaker=self.tiebreaker,
            use_candidate=self.controlling,
        )
        ok = endpoint.sendto(request, target.remote)
        now = time.monotonic()
        with self._lock:
            target.attempts += 1
            target.next_send = now + CHECK_INTERVAL
            self._pending[txid] = (target.key, now)
        if not ok:
            with self._lock:
                target.error = endpoint.last_error or "send failed"

    def handle(self, data: bytes, addr: tuple, endpoint: UdpEndpoint) -> bool:
        if len(data) < 20 or data[4:8] != b"\x21\x12\xa4\x42":
            return False
        try:
            message = parse_message(data)
        except StunError:
            return False
        if message.message_type == BINDING_REQUEST:
            username = message.get(ATTR_USERNAME)
            if username is None or username.decode("utf-8", "replace") != self.username:
                return True
            if not message_integrity_valid(message, self.password):
                return True
            if message.get(ATTR_FINGERPRINT) is not None and not has_valid_fingerprint(message):
                return True
            source_ip, source_port = addr_key(addr)
            response = build_binding_success(
                message.transaction_id,
                source_ip,
                source_port,
                password=self.password,
            )
            endpoint.sendto(response, addr)
            with self._lock:
                self._inbound_keys.add((endpoint.local_key, (source_ip, source_port)))
            return True
        if message.message_type in (BINDING_SUCCESS, BINDING_ERROR):
            with self._lock:
                pending = self._pending.pop(message.transaction_id, None)
            if pending is None:
                return True
            key, sent_at = pending
            with self._lock:
                target = self._targets.get(key)
            if target is None:
                return True
            source_ip, source_port = addr_key(addr)
            if (source_ip, source_port) != target.remote:
                return True
            if not message_integrity_valid(message, self.password):
                return True
            if message.message_type == BINDING_ERROR:
                error = message.error()
                with self._lock:
                    target.status = "failed"
                    target.error = f"STUN error {error[0]}: {error[1]}" if error else "STUN error"
                    target.finished = time.monotonic()
                return True
            if message.get(ATTR_FINGERPRINT) is not None and not has_valid_fingerprint(message):
                return True
            try:
                mapped = parse_address_from_response(message)
            except StunError as exc:
                with self._lock:
                    target.error = str(exc)
                return True
            rtt_ms = (time.monotonic() - sent_at) * 1000.0
            with self._lock:
                target.status = "succeeded"
                target.rtt_ms = rtt_ms
                target.mapped = mapped
                target.error = ""
                target.finished = time.monotonic()
            return True
        return False

    def _loop(self) -> None:
        while not self._stop.wait(0.08):
            now = time.monotonic()
            due: list[CheckTarget] = []
            failed: list[CheckTarget] = []
            with self._lock:
                for target in self._targets.values():
                    if target.status != "waiting":
                        continue
                    if now - target.started > CHECK_DEADLINE:
                        target.status = "failed"
                        if not target.error:
                            target.error = "no response before deadline"
                        target.finished = now
                        failed.append(target)
                    elif now >= target.next_send:
                        due.append(target)
            for target in due:
                self._send_check(target)
            # Expire pending transactions; the target will retry until its deadline.
            with self._lock:
                for txid, (_, sent_at) in list(self._pending.items()):
                    if now - sent_at > CHECK_INTERVAL * 2.5:
                        self._pending.pop(txid, None)

    def results(self) -> list[CheckTarget]:
        with self._lock:
            return sorted(
                self._targets.values(),
                key=lambda t: (-t.priority, t.status != "succeeded", t.rtt_ms or 1e9),
            )

    def successful(self) -> list[CheckTarget]:
        return [target for target in self.results() if target.status == "succeeded"]

    def failed(self) -> list[CheckTarget]:
        return [target for target in self.results() if target.status == "failed"]

    def inbound_from(self, local_key: str, addr: tuple) -> bool:
        with self._lock:
            return (local_key, addr_key(addr)) in self._inbound_keys

    def report_rows(self) -> list[dict]:
        rows = []
        for target in self.results():
            detail = f"{target.address}:{target.port}"
            if target.rtt_ms is not None:
                detail += f" rtt={target.rtt_ms:.0f}ms"
            if target.error:
                detail += f" ({target.error})"
            rows.append(
                {
                    "pair": f"{target.local_id} -> {target.remote_id}",
                    "protocol": "udp",
                    "status": target.status,
                    "detail": detail,
                }
            )
        return rows
