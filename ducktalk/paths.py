"""Candidate paths: UDP endpoints and TCP connections with ordered framing."""

from __future__ import annotations

import json
import queue
import socket
import struct
import threading
from collections.abc import Callable

from .candidates import b64d, b64e
from .transport import (
    MAGIC_CONTROL,
    MAX_UDP_PACKET,
    TransportError,
    UdpEndpoint,
)

MAX_CONTROL_BYTES = 16384
TCP_KIND_CONTROL = 0
TCP_KIND_NOISE = 1
TCP_KIND_SECURE = 2


class PathClosed(TransportError):
    pass


class BasePath:
    def __init__(self, on_control: Callable[[BasePath, dict], None], on_close: Callable[[BasePath, str], None]) -> None:
        self._on_control = on_control
        self._on_close = on_close
        self._closed = threading.Event()
        self._close_reason = ""
        self._secure_sink: Callable[[bytes], None] | None = None
        self._secure_buffer: list[bytes] = []
        self.noise_queue: queue.Queue[bytes | None] = queue.Queue()
        self._control_inbox: queue.Queue[dict | None] = queue.Queue()

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    @property
    def close_reason(self) -> str:
        return self._close_reason

    def attach_secure(self, sink: Callable[[bytes], None]) -> None:
        self._secure_sink = sink
        if self._secure_buffer:
            buffered, self._secure_buffer = self._secure_buffer, []
            for packet in buffered:
                try:
                    sink(packet)
                except Exception:
                    pass

    def detach_secure(self) -> None:
        self._secure_sink = None

    def push_control(self, message: dict) -> None:
        if not self._closed.is_set():
            self._control_inbox.put(message)

    def push_noise(self, data: bytes) -> None:
        if not self._closed.is_set():
            self.noise_queue.put(data)

    def push_secure(self, packet: bytes) -> None:
        sink = self._secure_sink
        if sink is not None:
            sink(packet)
            return
        if len(self._secure_buffer) < 64:
            self._secure_buffer.append(packet)

    def next_control(self, timeout: float) -> dict | None:
        try:
            return self._control_inbox.get(timeout=timeout)
        except queue.Empty:
            return None

    def next_noise(self, timeout: float) -> bytes | None:
        try:
            item = self.noise_queue.get(timeout=timeout)
        except queue.Empty:
            return None
        return item

    def send_control(self, message: dict) -> None:
        raise NotImplementedError

    def send_noise(self, data: bytes) -> None:
        raise NotImplementedError

    def send_secure(self, packet: bytes) -> None:
        raise NotImplementedError

    def describe(self) -> str:
        return "path"

    def _mark_closed(self, reason: str) -> None:
        if self._closed.is_set():
            return
        self._close_reason = reason
        self._closed.set()
        self._control_inbox.put(None)
        self.noise_queue.put(None)
        try:
            self._on_close(self, reason)
        except Exception:
            pass

    def close(self, reason: str = "closed locally") -> None:
        self._mark_closed(reason)


class UdpPath(BasePath):
    def __init__(
        self,
        endpoint: UdpEndpoint,
        remote: tuple,
        on_control: Callable[[BasePath, dict], None],
        on_close: Callable[[BasePath, str], None],
    ) -> None:
        super().__init__(on_control, on_close)
        self.endpoint = endpoint
        self.remote = (str(remote[0]), int(remote[1]))

    @property
    def key(self) -> tuple[str, str, int]:
        return self.endpoint.local_key, self.remote[0], self.remote[1]

    def describe(self) -> str:
        return f"UDP {self.remote[0]}:{self.remote[1]} via {self.endpoint.local_key}"

    def send_control(self, message: dict) -> None:
        if self._closed.is_set():
            raise PathClosed("UDP path is closed")
        raw = json.dumps(message, separators=(",", ":")).encode("utf-8")
        if len(raw) > MAX_CONTROL_BYTES:
            raise PathClosed("control message too large")
        packet = MAGIC_CONTROL + struct.pack(">I", len(raw)) + raw
        if not self.endpoint.sendto(packet, self.remote):
            raise PathClosed(self.endpoint.last_error or "UDP send failed")

    def send_noise(self, data: bytes) -> None:
        self.send_control({"v": 1, "type": "noise", "data": b64e(data)})

    def send_secure(self, packet: bytes) -> None:
        if self._closed.is_set():
            raise PathClosed("UDP path is closed")
        if len(packet) > MAX_UDP_PACKET:
            raise PathClosed("secure packet too large")
        if not self.endpoint.sendto(packet, self.remote):
            raise PathClosed(self.endpoint.last_error or "UDP send failed")

    def handle_control_payload(self, raw: bytes) -> None:
        if len(raw) > MAX_CONTROL_BYTES:
            return
        try:
            message = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        if not isinstance(message, dict):
            return
        if message.get("type") == "noise":
            try:
                self.push_noise(b64d(str(message.get("data", ""))))
            except Exception:
                return
            return
        self._on_control(self, message)

    def close(self, reason: str = "closed locally") -> None:
        self._mark_closed(reason)


class TcpPath(BasePath):
    def __init__(
        self,
        sock: socket.socket,
        on_control: Callable[[BasePath, dict], None],
        on_close: Callable[[BasePath, str], None],
        description: str = "TCP",
    ) -> None:
        super().__init__(on_control, on_close)
        self.sock = sock
        self.description = description
        self._send_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def describe(self) -> str:
        try:
            peer = self.sock.getpeername()
            return f"{self.description} {peer[0]}:{peer[1]}"
        except OSError:
            return self.description

    def start(self) -> None:
        if self._thread is not None:
            return
        try:
            self.sock.settimeout(1.0)
        except OSError:
            pass
        self._thread = threading.Thread(target=self._read_loop, name="tcp-path-rx", daemon=True)
        self._thread.start()

    def _send_frame(self, kind: int, payload: bytes) -> None:
        if self._closed.is_set():
            raise PathClosed("TCP path is closed")
        if len(payload) > 60000:
            raise PathClosed("TCP frame too large")
        frame = struct.pack(">I", 1 + len(payload)) + bytes([kind]) + payload
        with self._send_lock:
            try:
                self.sock.sendall(frame)
            except OSError as exc:
                self._mark_closed(f"TCP send failed: {exc}")
                raise PathClosed(str(exc)) from exc

    def send_control(self, message: dict) -> None:
        raw = json.dumps(message, separators=(",", ":")).encode("utf-8")
        if len(raw) > MAX_CONTROL_BYTES:
            raise PathClosed("control message too large")
        self._send_frame(TCP_KIND_CONTROL, raw)

    def send_noise(self, data: bytes) -> None:
        self._send_frame(TCP_KIND_NOISE, data)

    def send_secure(self, packet: bytes) -> None:
        self._send_frame(TCP_KIND_SECURE, packet)

    def _read_exact(self, count: int) -> bytes:
        data = bytearray()
        while len(data) < count:
            if self._stop.is_set():
                raise PathClosed("TCP path closed")
            try:
                chunk = self.sock.recv(count - len(data))
            except TimeoutError:
                continue
            except OSError as exc:
                raise PathClosed(f"TCP read failed: {exc}") from exc
            if not chunk:
                raise PathClosed("peer closed the TCP connection")
            data.extend(chunk)
        return bytes(data)

    def _read_loop(self) -> None:
        try:
            while not self._stop.is_set():
                header = self._read_exact(4)
                length = struct.unpack(">I", header)[0]
                if length < 1 or length > 65535:
                    raise PathClosed("invalid TCP frame length")
                body = self._read_exact(length)
                kind = body[0]
                payload = body[1:]
                if kind == TCP_KIND_CONTROL:
                    if len(payload) > MAX_CONTROL_BYTES:
                        continue
                    try:
                        message = json.loads(payload.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if isinstance(message, dict):
                        self._on_control(self, message)
                elif kind == TCP_KIND_NOISE:
                    self.push_noise(payload)
                elif kind == TCP_KIND_SECURE:
                    self.push_secure(payload)
        except PathClosed as exc:
            self._mark_closed(str(exc))
        except TransportError as exc:
            if not self._stop.is_set():
                self._mark_closed(str(exc))
        except OSError as exc:
            if not self._stop.is_set():
                self._mark_closed(f"TCP read failed: {exc}")
        except Exception as exc:
            if not self._stop.is_set():
                self._mark_closed(f"TCP path failed: {exc}")

    def close(self, reason: str = "closed locally") -> None:
        if self._closed.is_set():
            return
        self._stop.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
        self._mark_closed(reason)
