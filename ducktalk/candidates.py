"""ICE-style candidate model, local address gathering and invite codes."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import secrets
import socket
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

INVITE_PREFIX = "DTK1-"
MAX_INVITE_CHARS = 8192
MAX_CANDIDATES = 32
DEFAULT_DIRECT_PORT = 47777
QUICK_CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
QUICK_CODE_LENGTH = 10

TYPE_PREFERENCE = {"host": 126, "prflx": 110, "srflx": 100, "relay": 0}
VALID_PROTOCOLS = {"udp", "tcp"}
VALID_KINDS = set(TYPE_PREFERENCE)


class InviteError(ValueError):
    """Raised when an invite or candidate payload is invalid."""


def new_quick_code() -> str:
    return "".join(secrets.choice(QUICK_CODE_ALPHABET) for _ in range(QUICK_CODE_LENGTH))


def normalize_quick_code(code: str) -> str:
    cleaned = "".join(ch for ch in (code or "").upper() if ch.isalnum())
    if len(cleaned) != QUICK_CODE_LENGTH or any(
        ch not in QUICK_CODE_ALPHABET for ch in cleaned
    ):
        raise InviteError(
            f"join code must be {QUICK_CODE_LENGTH} letters/digits without ambiguous characters"
        )
    return cleaned


def format_quick_code(code: str) -> str:
    canonical = normalize_quick_code(code)
    return f"{canonical[:5]}-{canonical[5:]}"


def quick_identity(code: str) -> tuple[bytes, bytes]:
    canonical = normalize_quick_code(code)
    material = hashlib.sha256(b"DuckTalk/quick/v1\x00" + canonical.encode("ascii")).digest()
    return material[:16], material[16:]


def format_endpoint(address: str, port: int) -> str:
    if ":" in address:
        return f"[{address}]:{port}"
    return f"{address}:{port}"


def parse_endpoint(text: str, default_port: int = DEFAULT_DIRECT_PORT) -> tuple[str, int]:
    cleaned = (text or "").strip()
    if not cleaned:
        raise InviteError("address is required")
    host = cleaned
    port = default_port
    if cleaned.startswith("["):
        close = cleaned.find("]")
        if close < 0:
            raise InviteError("invalid bracketed IPv6 address")
        host = cleaned[1:close]
        suffix = cleaned[close + 1 :]
        if suffix:
            if not suffix.startswith(":"):
                raise InviteError("invalid address suffix")
            try:
                port = int(suffix[1:])
            except ValueError as exc:
                raise InviteError("invalid port") from exc
    elif cleaned.count(":") == 1:
        host, port_text = cleaned.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError as exc:
            raise InviteError("invalid port") from exc
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise InviteError("address must be an IPv4 or IPv6 address") from exc
    if ip.is_unspecified or ip.is_multicast:
        raise InviteError("address must be a unicast address")
    if ip.version == 6 and ip.is_link_local:
        raise InviteError("IPv6 link-local addresses require a scope id and are not supported")
    if not 1 <= port <= 65535:
        raise InviteError("port must be between 1 and 65535")
    return str(ip), port


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise InviteError("invalid base64 data") from exc


def sanitize_name(name: str, *, fallback: str = "peer") -> str:
    cleaned = "".join(ch for ch in (name or "").strip() if ch.isprintable())
    cleaned = cleaned[:40].strip()
    return cleaned or fallback


def short_fingerprint(public_key: bytes) -> str:
    digest = hashlib.sha256(public_key).hexdigest()[:16].upper()
    return " ".join(digest[i : i + 4] for i in range(0, 16, 4))


def _local_ip(family: int) -> str | None:
    target = ("8.8.8.8", 53) if family == 4 else ("2001:4860:4860::8888", 53)
    af = socket.AF_INET if family == 4 else socket.AF_INET6
    sock = socket.socket(af, socket.SOCK_DGRAM)
    try:
        sock.connect(target)
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def gather_host_addresses(family: int, allow_loopback: bool = False) -> list[str]:
    """Return usable unicast addresses for one address family."""

    addresses: list[str] = []
    route_ip = _local_ip(family)
    if route_ip:
        addresses.append(route_ip)
    if allow_loopback:
        addresses.append("127.0.0.1" if family == 4 else "::1")
    unique: list[str] = []
    for text in addresses:
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            continue
        if ip.is_unspecified or ip.is_multicast:
            continue
        if ip.version == 6 and ip.is_link_local:
            continue
        if text not in unique:
            unique.append(text)
    return unique


def candidate_priority(kind: str, family: int, address: str, protocol: str = "udp") -> int:
    type_pref = TYPE_PREFERENCE.get(kind, 0)
    local_pref = 65535 if family == 6 else 65534
    try:
        if ipaddress.ip_address(address).is_loopback:
            local_pref = 65533
    except ValueError:
        pass
    component = 1 if protocol == "udp" else 2
    return (type_pref << 24) | (local_pref << 8) | (256 - component)


def foundation(protocol: str, kind: str, address: str, family: int) -> str:
    digest = hashlib.sha1(f"{protocol}|{kind}|{address}|{family}".encode("ascii")).hexdigest()
    return digest[:8]


@dataclass
class Candidate:
    id: str
    protocol: str
    kind: str
    address: str
    port: int
    family: int
    priority: int
    foundation: str = ""
    local_key: str = ""

    def __post_init__(self) -> None:
        if not self.foundation:
            self.foundation = foundation(self.protocol, self.kind, self.address, self.family)

    @property
    def endpoint(self) -> tuple[str, int]:
        return self.address, self.port

    @property
    def is_local(self) -> bool:
        return bool(self.local_key)

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "proto": self.protocol,
            "kind": self.kind,
            "addr": self.address,
            "port": self.port,
            "family": self.family,
            "priority": self.priority,
        }
        if self.local_key:
            data["local"] = self.local_key
        return data

    @classmethod
    def from_json(cls, data: Any, *, local: bool = False) -> Candidate:
        if not isinstance(data, dict):
            raise InviteError("candidate must be an object")
        try:
            cid = str(data["id"])
            protocol = str(data["proto"]).lower()
            kind = str(data["kind"]).lower()
            address = str(data["addr"])
            port = int(data["port"])
            family = int(data["family"])
            priority = int(data.get("priority", 0))
        except (KeyError, TypeError, ValueError) as exc:
            raise InviteError("candidate has missing or invalid fields") from exc
        if not cid or len(cid) > 32 or not cid.isprintable():
            raise InviteError("invalid candidate id")
        if protocol not in VALID_PROTOCOLS:
            raise InviteError("invalid candidate protocol")
        if kind not in VALID_KINDS or kind == "relay":
            raise InviteError("relay candidates are not supported")
        if family not in (4, 6):
            raise InviteError("invalid candidate address family")
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise InviteError("invalid candidate address") from exc
        if ip.version != family:
            raise InviteError("candidate address family mismatch")
        if ip.is_unspecified or ip.is_multicast:
            raise InviteError("candidate address is not unicast")
        if ip.version == 6 and ip.is_link_local:
            raise InviteError("IPv6 link-local candidates require scope ids and are not supported")
        if not 1 <= port <= 65535:
            raise InviteError("candidate port out of range")
        if priority < 0:
            raise InviteError("invalid candidate priority")
        local_key = str(data.get("local", "")) if local else ""
        return cls(cid, protocol, kind, address, port, family, priority, local_key=local_key)

    def sort_key(self) -> tuple[int, int, int]:
        proto_rank = 0 if self.protocol == "udp" else 1
        return (-self.priority, proto_rank, 0)


@dataclass
class CandidatePair:
    local: Candidate
    remote: Candidate
    state: str = "waiting"
    attempts: int = 0
    rtt_ms: float | None = None
    error: str = ""
    mapped: tuple[str, int] | None = None
    bytes_sent: int = 0
    bytes_received: int = 0

    @property
    def key(self) -> tuple[str, str]:
        return self.local.id, self.remote.id

    @property
    def priority(self) -> int:
        g = self.local.priority
        d = self.remote.priority
        return (min(g, d) << 32) + (max(g, d) << 1) + (1 if g > d else 0)


def sort_candidates(candidates: Iterable[Candidate]) -> list[Candidate]:
    return sorted(candidates, key=lambda c: c.sort_key())


def make_candidate(
    *,
    cid: str,
    protocol: str,
    kind: str,
    address: str,
    port: int,
    local_key: str = "",
) -> Candidate:
    family = ipaddress.ip_address(address).version
    priority = candidate_priority(kind, family, address, protocol)
    return Candidate(cid, protocol, kind, address, port, family, priority, local_key=local_key)


@dataclass
class Invite:
    session_id: bytes
    token: bytes
    name: str
    static_public: bytes
    candidates: list[Candidate]
    created_at: int
    expires_at: int
    version: int = 1
    direct: bool = False

    def __post_init__(self) -> None:
        if len(self.session_id) != 16:
            raise InviteError("session id must be 16 bytes")
        if len(self.token) != 16:
            raise InviteError("token must be 16 bytes")
        if len(self.static_public) != 32:
            raise InviteError("static public key must be 32 bytes")
        if not 1 <= len(self.candidates) <= MAX_CANDIDATES:
            raise InviteError("invite must contain between 1 and 32 candidates")
        if self.version != 1:
            raise InviteError("unsupported invite version")

    def to_json(self) -> dict[str, Any]:
        return {
            "v": self.version,
            "sid": b64e(self.session_id),
            "token": b64e(self.token),
            "name": self.name,
            "static": b64e(self.static_public),
            "created": self.created_at,
            "expires": self.expires_at,
            "candidates": [c.to_json() for c in sort_candidates(self.candidates)],
            "note": "DuckTalk manual signalling. Contains endpoints and a session key, never chat messages.",
        }

    def encode(self) -> str:
        raw = json.dumps(self.to_json(), separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(raw) > MAX_INVITE_CHARS:
            raise InviteError("invite is too large")
        return INVITE_PREFIX + b64e(raw)

    def formatted(self, width: int = 76) -> str:
        code = self.encode()
        lines = [code[i : i + width] for i in range(0, len(code), width)]
        return "\n".join(lines)

    @classmethod
    def decode(cls, code: str, *, now: int | None = None) -> Invite:
        cleaned = "".join(code.split())
        cleaned = cleaned.removeprefix("ducktalk://join/")
        if not cleaned.startswith(INVITE_PREFIX):
            raise InviteError("invite must start with DTK1-")
        if len(cleaned) > MAX_INVITE_CHARS + len(INVITE_PREFIX):
            raise InviteError("invite is too large")
        payload = b64d(cleaned[len(INVITE_PREFIX) :])
        try:
            data = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InviteError("invite payload is not valid JSON") from exc
        if not isinstance(data, dict):
            raise InviteError("invite payload must be an object")
        if int(data.get("v", 0)) != 1:
            raise InviteError("unsupported invite version")
        try:
            sid = b64d(str(data["sid"]))
            token = b64d(str(data["token"]))
            static = b64d(str(data["static"]))
            name = sanitize_name(str(data["name"]))
            created = int(data["created"])
            expires = int(data["expires"])
            candidates_raw = data["candidates"]
        except (KeyError, TypeError, ValueError) as exc:
            raise InviteError("invite is missing required fields") from exc
        if not isinstance(candidates_raw, list) or not 1 <= len(candidates_raw) <= MAX_CANDIDATES:
            raise InviteError("invite has an invalid candidate list")
        candidates = [Candidate.from_json(item) for item in candidates_raw]
        ids = [c.id for c in candidates]
        if len(ids) != len(set(ids)):
            raise InviteError("invite has duplicate candidate ids")
        now = int(time.time()) if now is None else now
        if expires <= now:
            raise InviteError("invite has expired")
        if created > now + 300:
            raise InviteError("invite creation time is in the future")
        if expires - created > 7 * 24 * 3600:
            raise InviteError("invite validity is unreasonably long")
        return cls(sid, token, name, static, candidates, created, expires)

    @classmethod
    def direct_for(
        cls,
        address: str,
        port: int,
        code: str,
        *,
        include_udp: bool = True,
        include_tcp: bool = True,
    ) -> Invite:
        if not include_udp and not include_tcp:
            raise InviteError("at least one transport is required")
        normalized = normalize_quick_code(code)
        sid, token = quick_identity(normalized)
        ip = ipaddress.ip_address(address)
        if ip.is_unspecified or ip.is_multicast:
            raise InviteError("address must be a unicast address")
        if ip.version == 6 and ip.is_link_local:
            raise InviteError("IPv6 link-local addresses require a scope id and are not supported")
        family = ip.version
        candidates: list[Candidate] = []
        if include_udp:
            candidates.append(
                make_candidate(
                    cid=f"d{family}u",
                    protocol="udp",
                    kind="host",
                    address=address,
                    port=port,
                    local_key=f"udp{family}",
                )
            )
        if include_tcp:
            candidates.append(
                make_candidate(
                    cid=f"d{family}t",
                    protocol="tcp",
                    kind="host",
                    address=address,
                    port=port,
                    local_key=f"tcp{family}",
                )
            )
        now = int(time.time())
        return cls(
            sid,
            token,
            "",
            b"\x00" * 32,
            candidates,
            now,
            now + 3600,
            direct=True,
        )


def peer_fingerprint(static_public: bytes) -> str:
    return short_fingerprint(static_public)


@dataclass
class LocalCandidates:
    candidates: list[Candidate] = field(default_factory=list)

    def by_key(self, local_key: str) -> list[Candidate]:
        return [c for c in self.candidates if c.local_key == local_key]

    def udp(self) -> list[Candidate]:
        return [c for c in self.candidates if c.protocol == "udp"]

    def tcp(self) -> list[Candidate]:
        return [c for c in self.candidates if c.protocol == "tcp"]
