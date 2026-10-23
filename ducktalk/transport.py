"""Direct transports: UDP endpoint, reliable encrypted UDP, encrypted TCP."""

from __future__ import annotations

import os
import socket
import struct
import threading
import time
from collections.abc import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MAGIC_CONTROL = b"DTK1"
MAGIC_SECURE = b"DTK2"

FRAME_DATA = 1
FRAME_HELLO = 2
FRAME_BYE = 3
FRAME_PING = 4
FRAME_PONG = 5
FRAME_ACK = 6
FRAME_CONFIRM = 7

RELIABLE_TYPES = {FRAME_DATA, FRAME_HELLO, FRAME_BYE, FRAME_CONFIRM}
MAX_CHAT_BYTES = 900
MAX_CONTROL_FRAME = 4096
MAX_UDP_PACKET = 1400
MAX_RX_BUFFER = 512
HEARTBEAT_INTERVAL = 10.0
PEER_TIMEOUT = 40.0


class TransportError(Exception):
    """Raised when a direct transport fails."""


def addr_key(addr: tuple) -> tuple[str, int]:
    return str(addr[0]), int(addr[1])


def _nonce(counter: int) -> bytes:
    return b"\x00" * 4 + struct.pack(">Q", counter)


class UdpEndpoint:
    """One bound UDP socket with a single receive loop."""

    def __init__(self, family: int, bind_ip: str, local_key: str, port: int = 0) -> None:
        self.family = family
        self.local_key = local_key
        self.sock = socket.socket(
            socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM
        )
        self.sock.bind((bind_ip, port))
        self.sock.settimeout(0.2)
        self.local_port = int(self.sock.getsockname()[1])
        self._handler: Callable[[bytes, tuple], None] | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._send_lock = threading.Lock()
        self._last_error = ""

    @property
    def last_error(self) -> str:
        return self._last_error

    def start(self, handler: Callable[[bytes, tuple], None]) -> None:
        if self._thread is not None:
            raise RuntimeError("endpoint already started")
        self._handler = handler
        self._thread = threading.Thread(target=self._read_loop, name=f"udp-{self.local_key}", daemon=True)
        self._thread.start()

    def sendto(self, data: bytes, addr: tuple) -> bool:
        with self._send_lock:
            try:
                self.sock.sendto(data, addr)
                return True
            except OSError as exc:
                self._last_error = str(exc)
                return False

    def _read_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, source = self.sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError as exc:
                if self._stop.is_set():
                    break
                self._last_error = str(exc)
                time.sleep(0.05)
                continue
            if self._handler is not None and data:
                try:
                    self._handler(data, source)
                except Exception as exc:
                    self._last_error = f"handler error: {exc}"
                    if os.environ.get("DUCKTALK_DEBUG"):
                        print(f"[debug] UDP handler error: {exc}")

    def close(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=1.0)


class UdpSecureChannel:
    """Reliable, ordered, encrypted frames over a selected UDP candidate pair."""

    def __init__(
        self,
        endpoint: UdpEndpoint,
        remote: tuple,
        send_key: bytes,
        receive_key: bytes,
        *,
        on_frame: Callable[[int, bytes], None],
        on_close: Callable[[str], None],
    ) -> None:
        self.endpoint = endpoint
        self.remote = (str(remote[0]), int(remote[1]))
        self._send_key = send_key
        self._receive_key = receive_key
        self._on_frame = on_frame
        self._on_close = on_close
        self._send_lock = threading.Lock()
        self._recv_lock = threading.Lock()
        self._send_counter = 0
        self._recv_highest = -1
        self._recv_counters: set[int] = set()
        self._recv_next = 1
        self._recv_buffer: dict[int, tuple[int, bytes]] = {}
        self._seen_ids: set[int] = set()
        self._next_msg_id = 1
        self._pending: dict[int, dict] = {}
        self._ready = threading.Event()
        self._closed = threading.Event()
        self._stop = threading.Event()
        self._close_reason = ""
        self._last_recv = time.monotonic()
        self._last_send = 0.0
        self._last_ack_sent = 0.0
        self._timer: threading.Thread | None = None
        self._auth_failures = 0
        self._started = False

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    @property
    def ready(self) -> bool:
        return self._ready.is_set()

    @property
    def auth_failures(self) -> int:
        return self._auth_failures

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._timer = threading.Thread(target=self._timer_loop, name="udp-secure-timer", daemon=True)
        self._timer.start()
        self.send_frame(FRAME_HELLO, b"")

    def wait_ready(self, timeout: float) -> bool:
        return self._ready.wait(timeout)

    def _ack_fields(self) -> tuple[int, int]:
        with self._recv_lock:
            if not self._seen_ids and self._recv_next == 1:
                return 0, 0
            ack = max(self._recv_next - 1, max(self._seen_ids, default=0))
            bits = 0
            for offset in range(33):
                mid = ack - offset
                if mid < 1:
                    continue
                if mid < self._recv_next or mid in self._seen_ids:
                    bits |= 1 << offset
            return ack & 0xFFFFFFFF, bits & 0xFFFFFFFF

    def _encrypt_packet(self, frame_type: int, msg_id: int, payload: bytes) -> bytes:
        with self._send_lock:
            counter = self._send_counter
            self._send_counter += 1
            ack, bits = self._ack_fields()
            header = struct.pack(">BQII", frame_type, msg_id, ack, bits)
            plaintext = header + payload
            ad = MAGIC_SECURE + struct.pack(">Q", counter)
            ciphertext = ChaCha20Poly1305(self._send_key).encrypt(_nonce(counter), plaintext, ad)
            return ad + ciphertext

    def _send_now(self, frame_type: int, msg_id: int, payload: bytes) -> bool:
        packet = self._encrypt_packet(frame_type, msg_id, payload)
        if len(packet) > MAX_UDP_PACKET:
            raise TransportError("frame too large for a UDP datagram")
        ok = self.endpoint.sendto(packet, self.remote)
        self._last_send = time.monotonic()
        return ok

    def send_frame(self, frame_type: int, payload: bytes = b"") -> None:
        if self._closed.is_set():
            raise TransportError("channel is closed")
        if len(payload) > MAX_CONTROL_FRAME:
            raise TransportError("control payload too large")
        if frame_type == FRAME_DATA:
            if len(payload) > MAX_CHAT_BYTES:
                raise TransportError(f"message too long (max {MAX_CHAT_BYTES} UTF-8 bytes)")
            if not payload:
                raise TransportError("empty message")
        reliable = frame_type in RELIABLE_TYPES
        with self._send_lock:
            msg_id = self._next_msg_id if reliable else 0
            if reliable:
                self._next_msg_id += 1
                self._pending[msg_id] = {
                    "type": frame_type,
                    "payload": payload,
                    "attempts": 1,
                    "next": time.monotonic() + 0.35,
                }
        self._send_now(frame_type, msg_id, payload)

    def send_chat(self, text: str) -> None:
        encoded = text.encode("utf-8")
        self.send_frame(FRAME_DATA, encoded)

    def _send_ack(self) -> None:
        now = time.monotonic()
        if now - self._last_ack_sent < 0.02:
            return
        self._last_ack_sent = now
        try:
            self._send_now(FRAME_ACK, 0, b"")
        except TransportError:
            pass

    def receive(self, data: bytes, addr: tuple) -> None:
        if self._closed.is_set():
            return
        if addr_key(addr) != self.remote:
            return
        if not data.startswith(MAGIC_SECURE) or len(data) < 12 + 16:
            return
        counter = struct.unpack(">Q", data[4:12])[0]
        if counter in self._recv_counters or counter <= self._recv_highest - 4096:
            return
        try:
            plaintext = ChaCha20Poly1305(self._receive_key).decrypt(
                _nonce(counter), data[12:], data[:12]
            )
        except InvalidTag:
            self._auth_failures += 1
            return
        self._recv_counters.add(counter)
        self._recv_highest = max(self._recv_highest, counter)
        if len(self._recv_counters) > 8192:
            cutoff = self._recv_highest - 4096
            self._recv_counters = {c for c in self._recv_counters if c > cutoff}
        if len(plaintext) < 17:
            return
        frame_type, msg_id, ack, bits = struct.unpack(">BQII", plaintext[:17])
        payload = plaintext[17:]
        self._last_recv = time.monotonic()
        if frame_type == FRAME_ACK:
            self._handle_ack(ack, bits)
            return
        if frame_type == FRAME_PING:
            try:
                self._send_now(FRAME_PONG, 0, b"")
            except TransportError:
                pass
            return
        if frame_type == FRAME_PONG:
            return
        if frame_type not in RELIABLE_TYPES or msg_id == 0:
            return
        ready_frames: list[tuple[int, bytes]] = []
        with self._recv_lock:
            if msg_id >= self._recv_next and msg_id not in self._recv_buffer:
                self._seen_ids.add(msg_id)
                if msg_id == self._recv_next:
                    ready_frames.append((frame_type, payload))
                    self._recv_next += 1
                    while self._recv_next in self._recv_buffer:
                        ready_frames.append(self._recv_buffer.pop(self._recv_next))
                        self._recv_next += 1
                elif msg_id <= self._recv_next + MAX_RX_BUFFER:
                    self._recv_buffer[msg_id] = (frame_type, payload)
            cutoff = self._recv_next - 64
            if self._seen_ids:
                self._seen_ids = {mid for mid in self._seen_ids if mid >= cutoff}
        for ready_type, ready_payload in ready_frames:
            self._deliver(ready_type, ready_payload)
        self._send_ack()

    def _handle_ack(self, ack: int, bits: int) -> None:
        with self._send_lock:
            if ack <= 0:
                return
            for offset in range(33):
                if offset == 0 or bits & (1 << offset):
                    self._pending.pop(ack - offset, None)

    def _deliver(self, frame_type: int, payload: bytes) -> None:
        if frame_type == FRAME_HELLO:
            self._ready.set()
            return
        if frame_type == FRAME_BYE:
            self._finish("peer closed the session")
            return
        self._on_frame(frame_type, payload)

    def _timer_loop(self) -> None:
        while not self._stop.wait(0.1):
            if self._closed.is_set():
                continue
            now = time.monotonic()
            due = []
            with self._send_lock:
                for msg_id, item in list(self._pending.items()):
                    if now >= item["next"]:
                        due.append((msg_id, item["type"], item["payload"], item["attempts"]))
            for msg_id, frame_type, payload, attempts in due:
                if attempts >= 10:
                    self._finish("peer stopped acknowledging frames")
                    return
                okay = False
                try:
                    okay = self._send_now(frame_type, msg_id, payload)
                except TransportError:
                    okay = False
                with self._send_lock:
                    item = self._pending.get(msg_id)
                    if item is not None:
                        item["attempts"] = attempts + 1
                        item["next"] = time.monotonic() + min(0.35 * (1.6 ** (attempts - 1)), 2.5)
                if not okay:
                    continue
            if now - self._last_recv > PEER_TIMEOUT:
                self._finish("peer timed out")
                return
            if now - self._last_send > HEARTBEAT_INTERVAL:
                try:
                    self._send_now(FRAME_PING, 0, b"")
                except TransportError:
                    pass

    def _finish(self, reason: str) -> None:
        if self._closed.is_set():
            return
        self._close_reason = reason
        self._closed.set()
        self._ready.set()
        self._stop.set()
        try:
            self._on_close(reason)
        except Exception:
            pass

    def close(self, reason: str = "closed locally") -> None:
        if self._closed.is_set():
            return
        try:
            self.send_frame(FRAME_BYE, b"")
        except Exception:
            pass
        self._finish(reason)

    def fail(self, reason: str) -> None:
        self._finish(reason)


class TcpSecureChannel:
    """Encrypted frames over an established TCP connection."""

    def __init__(
        self,
        sock: socket.socket,
        send_key: bytes,
        receive_key: bytes,
        *,
        on_frame: Callable[[int, bytes], None],
        on_close: Callable[[str], None],
    ) -> None:
        self.sock = sock
        self._send_key = send_key
        self._receive_key = receive_key
        self._on_frame = on_frame
        self._on_close = on_close
        self._send_lock = threading.Lock()
        self._send_counter = 0
        self._recv_counter = 0
        self._next_msg_id = 1
        self._ready = threading.Event()
        self._closed = threading.Event()
        self._stop = threading.Event()
        self._last_recv = time.monotonic()
        self._thread: threading.Thread | None = None
        self._timer: threading.Thread | None = None
        self._started = False
        self._reason = ""

    @property
    def ready(self) -> bool:
        return self._ready.is_set()

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self.sock.settimeout(1.0)
        self._thread = threading.Thread(target=self._read_loop, name="tcp-secure-rx", daemon=True)
        self._thread.start()
        self._timer = threading.Thread(target=self._timer_loop, name="tcp-secure-timer", daemon=True)
        self._timer.start()
        self.send_frame(FRAME_HELLO, b"")

    def wait_ready(self, timeout: float) -> bool:
        return self._ready.wait(timeout)

    def _send_packet(self, frame_type: int, payload: bytes) -> None:
        if self._closed.is_set():
            raise TransportError("channel is closed")
        if len(payload) > MAX_CONTROL_FRAME:
            raise TransportError("control payload too large")
        if frame_type == FRAME_DATA:
            if not payload:
                raise TransportError("empty message")
            if len(payload) > MAX_CHAT_BYTES:
                raise TransportError(f"message too long (max {MAX_CHAT_BYTES} UTF-8 bytes)")
        with self._send_lock:
            counter = self._send_counter
            self._send_counter += 1
            msg_id = self._next_msg_id if frame_type in RELIABLE_TYPES else 0
            if frame_type in RELIABLE_TYPES:
                self._next_msg_id += 1
            plaintext = struct.pack(">BQ", frame_type, msg_id) + payload
            nonce = _nonce(counter)
            counter_bytes = struct.pack(">Q", counter)
            length = 8 + len(plaintext) + 16
            header = struct.pack(">I", length)
            ad = header + counter_bytes
            ciphertext = ChaCha20Poly1305(self._send_key).encrypt(nonce, plaintext, ad)
            frame = header + counter_bytes + ciphertext
            try:
                self.sock.sendall(frame)
            except OSError as exc:
                self._finish(f"TCP send failed: {exc}")
                raise TransportError(str(exc)) from exc

    def send_frame(self, frame_type: int, payload: bytes = b"") -> None:
        self._send_packet(frame_type, payload)

    def send_chat(self, text: str) -> None:
        self.send_frame(FRAME_DATA, text.encode("utf-8"))

    def _read_exact(self, count: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < count:
            if self._stop.is_set():
                raise TransportError("channel closed")
            try:
                chunk = self.sock.recv(count - len(chunks))
            except TimeoutError:
                continue
            except OSError as exc:
                raise TransportError(str(exc)) from exc
            if not chunk:
                raise TransportError("peer closed the TCP connection")
            chunks.extend(chunk)
        return bytes(chunks)

    def _read_loop(self) -> None:
        try:
            while not self._stop.is_set():
                header = self._read_exact(4)
                length = struct.unpack(">I", header)[0]
                if length < 8 + 16 or length > MAX_UDP_PACKET + 64:
                    raise TransportError("invalid TCP frame length")
                body = self._read_exact(length)
                counter = struct.unpack(">Q", body[:8])[0]
                if counter != self._recv_counter:
                    raise TransportError("TCP frame counter mismatch")
                self._recv_counter += 1
                plaintext = ChaCha20Poly1305(self._receive_key).decrypt(
                    _nonce(counter), body[8:], header + body[:8]
                )
                if len(plaintext) < 9:
                    continue
                frame_type = plaintext[0]
                payload = plaintext[9:]
                self._last_recv = time.monotonic()
                if frame_type == FRAME_HELLO:
                    self._ready.set()
                elif frame_type == FRAME_BYE:
                    self._finish("peer closed the session")
                    return
                elif frame_type == FRAME_PING:
                    self._send_packet(FRAME_PONG, b"")
                elif frame_type == FRAME_PONG or frame_type == FRAME_ACK:
                    pass
                else:
                    self._on_frame(frame_type, payload)
        except InvalidTag:
            self._finish("TCP authentication failed")
        except TransportError as exc:
            self._finish(str(exc))
        except Exception as exc:
            self._finish(f"TCP receive failed: {exc}")

    def _timer_loop(self) -> None:
        while not self._stop.wait(5.0):
            if self._closed.is_set():
                return
            if time.monotonic() - self._last_recv > PEER_TIMEOUT * 1.5:
                self._finish("peer timed out")
                return
            if time.monotonic() - self._last_recv > 15.0:
                try:
                    self._send_packet(FRAME_PING, b"")
                except TransportError:
                    return

    def _finish(self, reason: str) -> None:
        if self._closed.is_set():
            return
        self._reason = reason
        self._closed.set()
        self._ready.set()
        self._stop.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._on_close(reason)
        except Exception:
            pass

    def close(self, reason: str = "closed locally") -> None:
        if self._closed.is_set():
            return
        try:
            self.send_frame(FRAME_BYE, b"")
        except Exception:
            pass
        self._finish(reason)


def write_length_frame(sock: socket.socket, payload: bytes, timeout: float = 5.0) -> None:
    if len(payload) > 65535:
        raise TransportError("frame too large")
    sock.settimeout(timeout)
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def read_exact(sock: socket.socket, count: int, timeout: float) -> bytes:
    deadline = time.monotonic() + timeout
    data = bytearray()
    while len(data) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportError("timed out reading from TCP socket")
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(count - len(data))
        except TimeoutError as exc:
            raise TransportError("timed out reading from TCP socket") from exc
        if not chunk:
            raise TransportError("peer closed the TCP connection")
        data.extend(chunk)
    return bytes(data)


def read_length_frame(sock: socket.socket, timeout: float = 5.0, max_size: int = 65535) -> bytes:
    header = read_exact(sock, 4, timeout)
    length = struct.unpack(">I", header)[0]
    if length > max_size:
        raise TransportError("frame exceeds size limit")
    return read_exact(sock, length, timeout)


def tcp_connect(host: str, port: int, timeout: float) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
    except OSError:
        sock.close()
        raise
    return sock

MAGIC_TCP_SECURE = b"DTK2T"


class TcpPathSecureChannel:
    """Encrypted frame channel over a TcpPath (TCP already provides ordering)."""

    def __init__(self, path, send_key: bytes, receive_key: bytes, *, on_frame, on_close) -> None:
        self.path = path
        self._send_key = send_key
        self._receive_key = receive_key
        self._on_frame = on_frame
        self._on_close = on_close
        self._send_counter = 0
        self._recv_counter = 0
        self._next_msg_id = 1
        self._ready = threading.Event()
        self._closed = threading.Event()
        self._stop = threading.Event()
        self._last_recv = time.monotonic()
        self._last_send = 0.0
        self._send_lock = threading.Lock()
        self._timer: threading.Thread | None = None
        self._reason = ""
        self._started = False

    @property
    def ready(self) -> bool:
        return self._ready.is_set()

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self.path.attach_secure(self.receive_packet)
        self._timer = threading.Thread(target=self._timer_loop, name="tcp-path-secure-timer", daemon=True)
        self._timer.start()
        self.send_frame(FRAME_HELLO, b"")

    def wait_ready(self, timeout: float) -> bool:
        return self._ready.wait(timeout)

    def send_frame(self, frame_type: int, payload: bytes = b"") -> None:
        if self._closed.is_set():
            raise TransportError("channel is closed")
        if len(payload) > MAX_CONTROL_FRAME:
            raise TransportError("control payload too large")
        if frame_type == FRAME_DATA:
            if not payload:
                raise TransportError("empty message")
            if len(payload) > MAX_CHAT_BYTES:
                raise TransportError(f"message too long (max {MAX_CHAT_BYTES} UTF-8 bytes)")
        with self._send_lock:
            counter = self._send_counter
            self._send_counter += 1
            msg_id = self._next_msg_id if frame_type in RELIABLE_TYPES else 0
            if frame_type in RELIABLE_TYPES:
                self._next_msg_id += 1
            plaintext = struct.pack(">BQ", frame_type, msg_id) + payload
            ad = MAGIC_TCP_SECURE + struct.pack(">Q", counter)
            ct = ChaCha20Poly1305(self._send_key).encrypt(_nonce(counter), plaintext, ad)
            packet = struct.pack(">Q", counter) + ct
        try:
            self.path.send_secure(packet)
            self._last_send = time.monotonic()
        except Exception as exc:
            self._finish(f"TCP secure send failed: {exc}")
            raise TransportError(str(exc)) from exc

    def send_chat(self, text: str) -> None:
        self.send_frame(FRAME_DATA, text.encode("utf-8"))

    def receive_packet(self, packet: bytes) -> None:
        if self._closed.is_set() or len(packet) < 8 + 16:
            return
        counter = struct.unpack(">Q", packet[:8])[0]
        if counter != self._recv_counter:
            self._finish("TCP secure counter mismatch")
            return
        try:
            plaintext = ChaCha20Poly1305(self._receive_key).decrypt(
                _nonce(counter), packet[8:], MAGIC_TCP_SECURE + packet[:8]
            )
        except InvalidTag:
            self._finish("TCP authentication failed")
            return
        self._recv_counter += 1
        self._last_recv = time.monotonic()
        if len(plaintext) < 9:
            return
        frame_type = plaintext[0]
        payload = plaintext[9:]
        if frame_type == FRAME_HELLO:
            self._ready.set()
        elif frame_type == FRAME_BYE:
            self._finish("peer closed the session")
        elif frame_type == FRAME_PING:
            try:
                self.send_frame(FRAME_PONG, b"")
            except TransportError:
                pass
        elif frame_type == FRAME_PONG or frame_type == FRAME_ACK:
            pass
        else:
            self._on_frame(frame_type, payload)

    def _timer_loop(self) -> None:
        while not self._stop.wait(1.0):
            if self._closed.is_set():
                return
            now = time.monotonic()
            if now - self._last_recv > PEER_TIMEOUT:
                self._finish("peer timed out")
                return
            if now - max(self._last_recv, self._last_send) > HEARTBEAT_INTERVAL:
                try:
                    self.send_frame(FRAME_PING, b"")
                except TransportError:
                    return

    def _finish(self, reason: str) -> None:
        if self._closed.is_set():
            return
        self._reason = reason
        self._closed.set()
        self._ready.set()
        self._stop.set()
        try:
            self._on_close(reason)
        except Exception:
            pass

    def fail(self, reason: str) -> None:
        self._finish(reason)

    def close(self, reason: str = "closed locally") -> None:
        if self._closed.is_set():
            return
        try:
            self.send_frame(FRAME_BYE, b"")
        except Exception:
            pass
        self._finish(reason)
