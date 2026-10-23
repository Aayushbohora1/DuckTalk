"""Noise_XX_25519_ChaChaPoly_SHA256 handshake.

Implemented from the Noise Protocol Framework specification (revision 34)
using primitives from the maintained ``cryptography`` package. DuckTalk uses
XX so both peers contribute ephemeral keys and prove possession of their
static keys. Because static keys are generated per session, identity is
confirmed by comparing the derived SAS out of band; see docs/SECURITY.md.

The transport keys produced by ``split()`` are used by DuckTalk's own framing
(reliable UDP / stream TCP), never as a generic Noise transport stream.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PROTOCOL_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
HASHLEN = 32
MAX_NONCE = (1 << 64) - 1
SAS_CONTEXT = b"DuckTalk SAS v1\x00"


class NoiseError(Exception):
    """Raised for malformed handshake messages or failed authentication."""


def public_bytes(private: X25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def generate_static() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def _hkdf(ck: bytes, ikm: bytes, count: int) -> bytes:
    """Noise HKDF with the chaining key as salt and empty info."""

    if count < 1 or count > 255:
        raise ValueError("HKDF count out of range")
    prk = hmac.new(ck, ikm, hashlib.sha256).digest()
    output = b""
    block = b""
    for index in range(1, count + 1):
        block = hmac.new(prk, block + bytes([index]), hashlib.sha256).digest()
        output += block
    return output


def _mix_hash(h: bytes, data: bytes) -> bytes:
    return hashlib.sha256(h + data).digest()


def _aead_encrypt(key: bytes, nonce: int, ad: bytes, plaintext: bytes) -> bytes:
    nonce_bytes = b"\x00" * 4 + struct.pack("<Q", nonce)
    return ChaCha20Poly1305(key).encrypt(nonce_bytes, plaintext, ad)


def _aead_decrypt(key: bytes, nonce: int, ad: bytes, ciphertext: bytes) -> bytes:
    nonce_bytes = b"\x00" * 4 + struct.pack("<Q", nonce)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce_bytes, ciphertext, ad)
    except InvalidTag as exc:
        raise NoiseError("Noise authentication failed") from exc


def _dh(private: X25519PrivateKey, public: bytes) -> bytes:
    try:
        return private.exchange(X25519PublicKey.from_public_bytes(public))
    except Exception as exc:
        raise NoiseError("invalid X25519 public key") from exc


@dataclass(frozen=True)
class TransportKeys:
    send: bytes
    receive: bytes
    handshake_hash: bytes


class NoiseHandshake:
    def __init__(self, initiator: bool, static_private: X25519PrivateKey, prologue: bytes = b"") -> None:
        if len(PROTOCOL_NAME) > HASHLEN:
            self.h = hashlib.sha256(PROTOCOL_NAME).digest()
        else:
            self.h = PROTOCOL_NAME + b"\x00" * (HASHLEN - len(PROTOCOL_NAME))
        self.ck = self.h
        self.h = _mix_hash(self.h, prologue)
        self.initiator = initiator
        self.static_private = static_private
        self.static_public = public_bytes(static_private)
        self.ephemeral_private: X25519PrivateKey | None = None
        self.remote_ephemeral: bytes | None = None
        self.remote_static: bytes | None = None
        self._key: bytes | None = None
        self._nonce = 0
        self._message_index = 0
        self._finished = False
        self._sas_cache: str | None = None

    @property
    def is_finished(self) -> bool:
        return self._finished

    @property
    def handshake_hash(self) -> bytes:
        if not self._finished:
            raise NoiseError("handshake is not complete")
        return self.h

    def _set_key(self, key: bytes) -> None:
        self._key = key
        self._nonce = 0

    def _mix_key(self, dh_output: bytes) -> None:
        material = _hkdf(self.ck, dh_output, 2)
        self.ck, temp = material[:HASHLEN], material[HASHLEN:]
        self._set_key(temp)

    def _encrypt_and_hash(self, plaintext: bytes) -> bytes:
        if self._key is None:
            ciphertext = plaintext
        else:
            if self._nonce > MAX_NONCE:
                raise NoiseError("nonce exhausted")
            ciphertext = _aead_encrypt(self._key, self._nonce, self.h, plaintext)
            self._nonce += 1
        self.h = _mix_hash(self.h, ciphertext)
        return ciphertext

    def _decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        if self._key is None:
            plaintext = ciphertext
        else:
            if self._nonce > MAX_NONCE:
                raise NoiseError("nonce exhausted")
            plaintext = _aead_decrypt(self._key, self._nonce, self.h, ciphertext)
            self._nonce += 1
        self.h = _mix_hash(self.h, ciphertext)
        return plaintext

    def _write_e(self) -> bytes:
        self.ephemeral_private = X25519PrivateKey.generate()
        public = public_bytes(self.ephemeral_private)
        self.h = _mix_hash(self.h, public)
        return public

    def _read_e(self, message: bytes, offset: int) -> int:
        if len(message) < offset + 32:
            raise NoiseError("truncated ephemeral key")
        self.remote_ephemeral = message[offset : offset + 32]
        self.h = _mix_hash(self.h, self.remote_ephemeral)
        return offset + 32

    def _write_s(self) -> bytes:
        return self._encrypt_and_hash(self.static_public)

    def _read_s(self, message: bytes, offset: int) -> int:
        length = 48 if self._key is not None else 32
        if len(message) < offset + length:
            raise NoiseError("truncated static key")
        enc = message[offset : offset + length]
        plaintext = self._decrypt_and_hash(enc)
        if len(plaintext) != 32:
            raise NoiseError("invalid static key length")
        if self.remote_static is not None:
            raise NoiseError("duplicate static key")
        self.remote_static = plaintext
        return offset + length

    def _ee(self) -> None:
        if self.ephemeral_private is None or self.remote_ephemeral is None:
            raise NoiseError("ephemeral keys missing")
        self._mix_key(_dh(self.ephemeral_private, self.remote_ephemeral))

    def _es(self) -> None:
        if self.initiator:
            if self.ephemeral_private is None or self.remote_static is None:
                raise NoiseError("keys missing for es")
            self._mix_key(_dh(self.ephemeral_private, self.remote_static))
        else:
            if self.ephemeral_private is None or self.remote_ephemeral is None:
                raise NoiseError("keys missing for es")
            self._mix_key(_dh(self.static_private, self.remote_ephemeral))

    def _se(self) -> None:
        if self.initiator:
            if self.ephemeral_private is None or self.remote_static is None:
                raise NoiseError("keys missing for se")
            self._mix_key(_dh(self.static_private, self.remote_ephemeral))  # type: ignore[arg-type]
        else:
            if self.ephemeral_private is None or self.remote_static is None:
                raise NoiseError("keys missing for se")
            self._mix_key(_dh(self.ephemeral_private, self.remote_static))

    def write_message(self, payload: bytes = b"") -> bytes:
        if self._finished:
            raise NoiseError("handshake already complete")
        allowed = (self.initiator and self._message_index in (0, 2)) or (
            not self.initiator and self._message_index == 1
        )
        if not allowed:
            raise NoiseError("not this side's turn to write")
        if self._message_index == 0:
            message = self._write_e()
            message += self._encrypt_and_hash(payload)
        elif self._message_index == 1:
            message = self._write_e()
            self._ee()
            message += self._write_s()
            self._es()
            message += self._encrypt_and_hash(payload)
        else:
            message = self._write_s()
            self._se()
            message += self._encrypt_and_hash(payload)
        self._message_index += 1
        if self._message_index == 3:
            self._finished = True
        return message

    def read_message(self, message: bytes) -> bytes:
        if self._finished:
            raise NoiseError("handshake already complete")
        allowed = (self.initiator and self._message_index == 1) or (
            not self.initiator and self._message_index in (0, 2)
        )
        if not allowed:
            raise NoiseError("not this side's turn to read")
        offset = 0
        if self._message_index == 0:
            offset = self._read_e(message, offset)
            payload = self._decrypt_and_hash(message[offset:])
        elif self._message_index == 1:
            offset = self._read_e(message, offset)
            self._ee()
            offset = self._read_s(message, offset)
            self._es()
            payload = self._decrypt_and_hash(message[offset:])
        else:
            offset = self._read_s(message, offset)
            self._se()
            payload = self._decrypt_and_hash(message[offset:])
        self._message_index += 1
        if self._message_index == 3:
            self._finished = True
        return payload

    def split(self) -> TransportKeys:
        if not self._finished:
            raise NoiseError("handshake is not complete")
        material = _hkdf(self.ck, b"", 2)
        first, second = material[:HASHLEN], material[HASHLEN:]
        if self.initiator:
            return TransportKeys(send=first, receive=second, handshake_hash=self.h)
        return TransportKeys(send=second, receive=first, handshake_hash=self.h)

    def sas_code(self) -> str:
        """Return an 8-digit short authentication string bound to the handshake."""

        if not self._finished:
            raise NoiseError("handshake is not complete")
        if self.remote_static is None:
            raise NoiseError("remote static key missing")
        if self.initiator:
            initiator_static = self.static_public
            responder_static = self.remote_static
        else:
            initiator_static = self.remote_static
            responder_static = self.static_public
        if self._sas_cache is None:
            digest = hashlib.sha256(
                SAS_CONTEXT + self.h + initiator_static + responder_static
            ).digest()
            value = int.from_bytes(digest[:5], "big") % 100_000_000
            digits = f"{value:08d}"
            self._sas_cache = f"{digits[:4]} {digits[4:]}"
        return self._sas_cache
