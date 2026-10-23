"""Minimal RFC 5389 STUN support used by DuckTalk.

This module implements the subset DuckTalk needs:

* Binding requests/responses for public endpoint discovery.
* XOR-MAPPED-ADDRESS and MAPPED-ADDRESS encoding/decoding for IPv4 and IPv6.
* MESSAGE-INTEGRITY (HMAC-SHA1, RFC 5389 short-term credentials) and
  FINGERPRINT validation.
* Peer-to-peer Binding requests used as ICE-style connectivity checks.

It is deliberately not a complete ICE agent (no TURN, no nomination state
machine beyond a controller-selected pair). See docs/LIMITATIONS.md.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import socket
import struct
import time
import zlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

MAGIC_COOKIE = 0x2112A442
FINGERPRINT_XOR = 0x5354554E

BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
BINDING_ERROR = 0x0111

ATTR_MAPPED_ADDRESS = 0x0001
ATTR_RESPONSE_ADDRESS = 0x0002
ATTR_CHANGE_REQUEST = 0x0003
ATTR_SOURCE_ADDRESS = 0x0004
ATTR_CHANGED_ADDRESS = 0x0005
ATTR_USERNAME = 0x0006
ATTR_PASSWORD = 0x0007
ATTR_MESSAGE_INTEGRITY = 0x0008
ATTR_ERROR_CODE = 0x0009
ATTR_UNKNOWN_ATTRIBUTES = 0x000A
ATTR_REFLECTED_FROM = 0x000B
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_PRIORITY = 0x0024
ATTR_USE_CANDIDATE = 0x0025
ATTR_SOFTWARE = 0x8022
ATTR_FINGERPRINT = 0x8028
ATTR_ICE_CONTROLLED = 0x8029
ATTR_ICE_CONTROLLING = 0x802A

FAMILY_IPV4 = 0x01
FAMILY_IPV6 = 0x02

DEFAULT_STUN_SERVERS: tuple[str, ...] = (
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun.nextcloud.com:443",
)

SOFTWARE = b"DuckTalk/1"


class StunError(Exception):
    """Raised when a STUN message is malformed or fails authentication."""


@dataclass(frozen=True)
class StunAttribute:
    type: int
    value: bytes
    offset: int


@dataclass(frozen=True)
class StunMessage:
    message_type: int
    transaction_id: bytes
    attributes: tuple[StunAttribute, ...]
    raw: bytes

    def get(self, attr_type: int) -> bytes | None:
        for attribute in self.attributes:
            if attribute.type == attr_type:
                return attribute.value
        return None

    def get_all(self, attr_type: int) -> list[bytes]:
        return [a.value for a in self.attributes if a.type == attr_type]

    def error(self) -> tuple[int, str] | None:
        value = self.get(ATTR_ERROR_CODE)
        if value is None or len(value) < 4:
            return None
        number = value[2] & 0x7F
        klass = value[3] & 0x07
        code = klass * 100 + number
        reason = value[4:].decode("utf-8", "replace")
        return code, reason


@dataclass(frozen=True)
class StunObservation:
    server: str
    family: int
    mapped_ip: str | None
    mapped_port: int | None
    local_ip: str | None
    local_port: int | None
    rtt_ms: float | None
    software: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.mapped_ip is not None and self.error is None

    @property
    def mapped(self) -> tuple[str, int] | None:
        if self.mapped_ip is None or self.mapped_port is None:
            return None
        return self.mapped_ip, self.mapped_port


def transaction_id() -> bytes:
    return os.urandom(12)


def _pad(data: bytes) -> bytes:
    remainder = len(data) % 4
    return data + (b"\x00" * (4 - remainder) if remainder else b"")


def _header(message_type: int, length: int, txid: bytes) -> bytes:
    if len(txid) != 12:
        raise StunError("transaction id must be 12 bytes")
    return struct.pack("!HHI", message_type, length, MAGIC_COOKIE) + txid


def encode_attribute(attr_type: int, value: bytes) -> bytes:
    if not 0 <= attr_type <= 0xFFFF:
        raise StunError("attribute type out of range")
    if len(value) > 0xFFFF:
        raise StunError("attribute too large")
    return struct.pack("!HH", attr_type, len(value)) + _pad(value)


def parse_message(data: bytes) -> StunMessage:
    if len(data) < 20:
        raise StunError("message shorter than STUN header")
    if len(data) % 4:
        raise StunError("message is not 4-byte aligned")
    message_type, length, cookie = struct.unpack("!HHI", data[:8])
    if cookie != MAGIC_COOKIE:
        raise StunError("bad magic cookie")
    if length + 20 != len(data):
        raise StunError("length field does not match datagram")
    txid = data[8:20]
    attributes: list[StunAttribute] = []
    offset = 20
    while offset < len(data):
        if offset + 4 > len(data):
            raise StunError("truncated attribute header")
        attr_type, attr_len = struct.unpack("!HH", data[offset : offset + 4])
        value_start = offset + 4
        value_end = value_start + attr_len
        padded_end = value_end + ((4 - attr_len % 4) % 4)
        if padded_end > len(data):
            raise StunError("truncated attribute value")
        attributes.append(StunAttribute(attr_type, data[value_start:value_end], offset))
        offset = padded_end
    return StunMessage(message_type, txid, tuple(attributes), data)


def _add_message_integrity(base: bytes, password: bytes) -> bytes:
    """Append MESSAGE-INTEGRITY to a fully encoded header+attributes blob."""

    if len(base) < 20:
        raise StunError("base message too short")
    # The length in the header must include the 24-byte MI attribute when the
    # HMAC is computed, but must not include a later FINGERPRINT.
    header = bytearray(base[:20])
    body = base[20:]
    struct.pack_into("!H", header, 2, len(body) + 24)
    digest = hmac.new(password, bytes(header) + body, hashlib.sha1).digest()
    return bytes(header) + body + encode_attribute(ATTR_MESSAGE_INTEGRITY, digest)


def _add_fingerprint(base: bytes) -> bytes:
    if len(base) < 20:
        raise StunError("base message too short")
    header = bytearray(base[:20])
    body = base[20:]
    struct.pack_into("!H", header, 2, len(body) + 8)
    checksum = (zlib.crc32(bytes(header) + body) & 0xFFFFFFFF) ^ FINGERPRINT_XOR
    return bytes(header) + body + encode_attribute(ATTR_FINGERPRINT, struct.pack("!I", checksum))


def has_valid_fingerprint(message: StunMessage) -> bool:
    value = message.get(ATTR_FINGERPRINT)
    if value is None:
        return False
    if len(value) != 4:
        return False
    fingerprint_attr = next((a for a in message.attributes if a.type == ATTR_FINGERPRINT), None)
    if fingerprint_attr is None:
        return False
    if fingerprint_attr.offset != len(message.raw) - 8:
        return False
    prefix = bytearray(message.raw[: fingerprint_attr.offset])
    if len(prefix) < 20:
        return False
    struct.pack_into("!H", prefix, 2, fingerprint_attr.offset + 8 - 20)
    expected = (zlib.crc32(bytes(prefix)) & 0xFFFFFFFF) ^ FINGERPRINT_XOR
    return hmac.compare_digest(value, struct.pack("!I", expected))


def message_integrity_valid(message: StunMessage, password: bytes) -> bool:
    integrity = next((a for a in message.attributes if a.type == ATTR_MESSAGE_INTEGRITY), None)
    if integrity is None or len(integrity.value) != 20:
        return False
    mi_end = integrity.offset + 24
    if mi_end > len(message.raw):
        return False
    prefix = bytearray(message.raw[: integrity.offset])
    if len(prefix) < 20:
        return False
    struct.pack_into("!H", prefix, 2, mi_end - 20)
    digest = hmac.new(password, bytes(prefix), hashlib.sha1).digest()
    return hmac.compare_digest(digest, integrity.value)


def encode_xor_mapped_address(address: str, port: int, txid: bytes) -> bytes:
    ip = ipaddress.ip_address(address)
    cookie = struct.pack("!I", MAGIC_COOKIE)
    xport = port ^ (MAGIC_COOKIE >> 16)
    if ip.version == 4:
        value = bytes([0, FAMILY_IPV4]) + struct.pack("!H", xport)
        value += bytes(a ^ b for a, b in zip(ip.packed, cookie))
    else:
        value = bytes([0, FAMILY_IPV6]) + struct.pack("!H", xport)
        mask = cookie + txid
        value += bytes(a ^ b for a, b in zip(ip.packed, mask))
    return value


def decode_xor_mapped_address(value: bytes, txid: bytes) -> tuple[str, int]:
    if len(value) < 4:
        raise StunError("XOR-MAPPED-ADDRESS too short")
    family = value[1]
    xport = struct.unpack("!H", value[2:4])[0]
    port = xport ^ (MAGIC_COOKIE >> 16)
    cookie = struct.pack("!I", MAGIC_COOKIE)
    if family == FAMILY_IPV4:
        if len(value) < 8:
            raise StunError("IPv4 XOR-MAPPED-ADDRESS too short")
        raw = bytes(a ^ b for a, b in zip(value[4:8], cookie))
        return str(ipaddress.IPv4Address(raw)), port
    if family == FAMILY_IPV6:
        if len(value) < 20:
            raise StunError("IPv6 XOR-MAPPED-ADDRESS too short")
        mask = cookie + txid
        raw = bytes(a ^ b for a, b in zip(value[4:20], mask))
        return str(ipaddress.IPv6Address(raw)), port
    raise StunError("unknown address family")


def encode_mapped_address(address: str, port: int) -> bytes:
    ip = ipaddress.ip_address(address)
    family = FAMILY_IPV4 if ip.version == 4 else FAMILY_IPV6
    return bytes([0, family]) + struct.pack("!H", port) + ip.packed


def decode_mapped_address(value: bytes) -> tuple[str, int]:
    if len(value) < 4:
        raise StunError("MAPPED-ADDRESS too short")
    family = value[1]
    port = struct.unpack("!H", value[2:4])[0]
    if family == FAMILY_IPV4:
        if len(value) < 8:
            raise StunError("IPv4 MAPPED-ADDRESS too short")
        return str(ipaddress.IPv4Address(value[4:8])), port
    if family == FAMILY_IPV6:
        if len(value) < 20:
            raise StunError("IPv6 MAPPED-ADDRESS too short")
        return str(ipaddress.IPv6Address(value[4:20])), port
    raise StunError("unknown address family")


def encode_error_code(code: int, reason: str) -> bytes:
    klass = code // 100
    number = code % 100
    return bytes([0, 0, (klass & 0x07) << 5 | (number & 0x1F)]) + reason.encode("utf-8")


def _finalize(
    message_type: int,
    txid: bytes,
    attrs: Sequence[bytes],
    password: bytes | None,
    fingerprint: bool,
) -> bytes:
    body = b"".join(attrs)
    base = _header(message_type, len(body), txid) + body
    if password is not None:
        base = _add_message_integrity(base, password)
    if fingerprint:
        base = _add_fingerprint(base)
    return base


def build_binding_request(
    txid: bytes | None = None,
    *,
    username: str | None = None,
    password: bytes | None = None,
    priority: int | None = None,
    controlling: bool | None = None,
    tiebreaker: int | None = None,
    use_candidate: bool = False,
    software: bytes = SOFTWARE,
) -> tuple[bytes, bytes]:
    txid = txid or transaction_id()
    attrs: list[bytes] = []
    if username is not None:
        attrs.append(encode_attribute(ATTR_USERNAME, username.encode("utf-8")))
    if priority is not None:
        attrs.append(encode_attribute(ATTR_PRIORITY, struct.pack("!I", priority & 0xFFFFFFFF)))
    if controlling is True:
        attrs.append(encode_attribute(ATTR_ICE_CONTROLLING, struct.pack("!Q", tiebreaker or 0)))
    elif controlling is False:
        attrs.append(encode_attribute(ATTR_ICE_CONTROLLED, struct.pack("!Q", tiebreaker or 0)))
    if use_candidate:
        attrs.append(encode_attribute(ATTR_USE_CANDIDATE, b""))
    if software:
        attrs.append(encode_attribute(ATTR_SOFTWARE, software))
    return _finalize(BINDING_REQUEST, txid, attrs, password, fingerprint=True), txid


def build_binding_success(
    txid: bytes,
    mapped_address: str,
    mapped_port: int,
    *,
    password: bytes | None = None,
    software: bytes = SOFTWARE,
) -> bytes:
    attrs = [
        encode_attribute(ATTR_XOR_MAPPED_ADDRESS, encode_xor_mapped_address(mapped_address, mapped_port, txid)),
        encode_attribute(ATTR_MAPPED_ADDRESS, encode_mapped_address(mapped_address, mapped_port)),
    ]
    if software:
        attrs.append(encode_attribute(ATTR_SOFTWARE, software))
    return _finalize(BINDING_SUCCESS, txid, attrs, password, fingerprint=True)


def build_binding_error(
    txid: bytes,
    code: int,
    reason: str,
    *,
    password: bytes | None = None,
) -> bytes:
    attrs = [encode_attribute(ATTR_ERROR_CODE, encode_error_code(code, reason))]
    return _finalize(BINDING_ERROR, txid, attrs, password, fingerprint=True)


def parse_address_from_response(message: StunMessage) -> tuple[str, int]:
    value = message.get(ATTR_XOR_MAPPED_ADDRESS)
    if value is not None:
        return decode_xor_mapped_address(value, message.transaction_id)
    value = message.get(ATTR_MAPPED_ADDRESS)
    if value is not None:
        return decode_mapped_address(value)
    raise StunError("response has no mapped address")


def _resolve_server(host: str, port: int, family: int) -> tuple[int, tuple]:
    family_const = socket.AF_INET if family == 4 else socket.AF_INET6
    infos = socket.getaddrinfo(host, port, family_const, socket.SOCK_DGRAM)
    if not infos:
        raise StunError(f"could not resolve {host}")
    sockaddr = infos[0][4]
    return family_const, sockaddr


def stun_discover_on_socket(
    sock: socket.socket,
    server: str,
    family: int = 4,
    timeout: float = 1.5,
) -> StunObservation:
    """Ask one STUN server for a mapping using an existing bound UDP socket."""

    host, _, port_text = server.partition(":")
    try:
        port = int(port_text or "3478")
    except ValueError:
        return StunObservation(server, family, None, None, None, None, None, error="invalid server port")
    request, txid = build_binding_request()
    started = time.monotonic()
    try:
        af, sockaddr = _resolve_server(host, port, family)
        if af != sock.family:
            return StunObservation(server, family, None, None, None, None, None,
                                   error="server address family mismatch")
        sock.settimeout(timeout)
        local_ip, local_port = sock.getsockname()[:2]
        sock.sendto(request, sockaddr)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            data, source = sock.recvfrom(4096)
            if source[0] != sockaddr[0] or source[1] != sockaddr[1]:
                continue
            try:
                message = parse_message(data)
            except StunError:
                continue
            if message.transaction_id != txid:
                continue
            if message.message_type == BINDING_ERROR:
                error = message.error()
                reason = f"{error[0]} {error[1]}" if error else "STUN error"
                return StunObservation(server, family, None, None, local_ip, local_port, None, error=reason)
            if message.message_type != BINDING_SUCCESS:
                continue
            if message.get(ATTR_FINGERPRINT) is not None and not has_valid_fingerprint(message):
                return StunObservation(server, family, None, None, local_ip, local_port, None,
                                       error="invalid STUN fingerprint")
            try:
                mapped_ip, mapped_port = parse_address_from_response(message)
            except StunError as exc:
                return StunObservation(server, family, None, None, local_ip, local_port, None, error=str(exc))
            software_attr = message.get(ATTR_SOFTWARE)
            software = software_attr.decode("utf-8", "replace") if software_attr else None
            rtt_ms = (time.monotonic() - started) * 1000.0
            return StunObservation(
                server, family, mapped_ip, mapped_port, local_ip, local_port, rtt_ms, software=software
            )
        return StunObservation(server, family, None, None, local_ip, local_port, None,
                               error="no response (UDP blocked, firewall, or server unreachable)")
    except TimeoutError:
        return StunObservation(server, family, None, None, None, None, None,
                               error="no response (UDP blocked, firewall, or server unreachable)")
    except OSError as exc:
        return StunObservation(server, family, None, None, None, None, None, error=f"network error: {exc}")
    except StunError as exc:
        return StunObservation(server, family, None, None, None, None, None, error=str(exc))


def stun_discover(
    server: str,
    family: int = 4,
    timeout: float = 1.5,
) -> StunObservation:
    """Ask one STUN server for our mapping using a fresh UDP socket."""

    host, _, port_text = server.partition(":")
    try:
        port = int(port_text or "3478")
    except ValueError:
        return StunObservation(server, family, None, None, None, None, None, error="invalid server port")
    sock: socket.socket | None = None
    try:
        af, _ = _resolve_server(host, port, family)
        sock = socket.socket(af, socket.SOCK_DGRAM)
        if af == socket.AF_INET:
            sock.bind(("0.0.0.0", 0))
        else:
            sock.bind(("::", 0))
        return stun_discover_on_socket(sock, server, family=family, timeout=timeout)
    except TimeoutError:
        return StunObservation(server, family, None, None, None, None, None,
                               error="no response (UDP blocked, firewall, or server unreachable)")
    except OSError as exc:
        return StunObservation(server, family, None, None, None, None, None, error=f"network error: {exc}")
    except StunError as exc:
        return StunObservation(server, family, None, None, None, None, None, error=str(exc))
    finally:
        if sock is not None:
            sock.close()


def parse_server_spec(spec: str, default_port: int = 3478) -> tuple[str, int]:
    host, _, port_text = spec.strip().partition(":")
    if not host:
        raise ValueError("empty STUN server")
    port = int(port_text) if port_text else default_port
    if not 1 <= port <= 65535:
        raise ValueError("STUN port out of range")
    return host, port


def discover_all(servers: Iterable[str], family: int, timeout: float = 1.5) -> list[StunObservation]:
    results: list[StunObservation] = []
    for server in servers:
        results.append(stun_discover(server, family=family, timeout=timeout))
    return results
