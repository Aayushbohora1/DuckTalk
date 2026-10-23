from __future__ import annotations

import pytest

from ducktalk.noise import (
    NoiseError,
    NoiseHandshake,
    generate_static,
    public_bytes,
)


def complete_handshake(
    prologue: bytes = b"test",
    initiator_key=None,
    responder_key=None,
) -> tuple[NoiseHandshake, NoiseHandshake]:
    initiator_key = initiator_key or generate_static()
    responder_key = responder_key or generate_static()
    initiator = NoiseHandshake(True, initiator_key, prologue)
    responder = NoiseHandshake(False, responder_key, prologue)
    msg1 = initiator.write_message(b"")
    assert responder.read_message(msg1) == b""
    msg2 = responder.write_message(b"")
    assert initiator.read_message(msg2) == b""
    msg3 = initiator.write_message(b"")
    assert responder.read_message(msg3) == b""
    return initiator, responder


def test_noise_xx_completes_and_matches_sas() -> None:
    initiator, responder = complete_handshake()
    assert initiator.is_finished and responder.is_finished
    assert initiator.sas_code() == responder.sas_code()
    assert initiator.remote_static == responder.static_public
    assert responder.remote_static == initiator.static_public
    keys_i = initiator.split()
    keys_r = responder.split()
    assert keys_i.send == keys_r.receive
    assert keys_i.receive == keys_r.send
    assert keys_i.handshake_hash == keys_r.handshake_hash


def test_mismatched_prologues_fail() -> None:
    initiator = NoiseHandshake(True, generate_static(), b"one")
    responder = NoiseHandshake(False, generate_static(), b"two")
    msg1 = initiator.write_message(b"")
    responder.read_message(msg1)
    msg2 = responder.write_message(b"")
    with pytest.raises(NoiseError):
        initiator.read_message(msg2)


def test_tampered_message_is_rejected() -> None:
    initiator = NoiseHandshake(True, generate_static(), b"test")
    responder = NoiseHandshake(False, generate_static(), b"test")
    msg1 = initiator.write_message(b"")
    responder.read_message(msg1)
    msg2 = responder.write_message(b"")
    tampered = bytearray(msg2)
    tampered[-1] ^= 0xFF
    with pytest.raises(NoiseError):
        initiator.read_message(bytes(tampered))


def test_replayed_handshake_message_is_rejected() -> None:
    initiator = NoiseHandshake(True, generate_static(), b"test")
    responder = NoiseHandshake(False, generate_static(), b"test")
    msg1 = initiator.write_message(b"")
    responder.read_message(msg1)
    with pytest.raises(NoiseError):
        responder.read_message(msg1)


def test_split_requires_finished_handshake() -> None:
    handshake = NoiseHandshake(True, generate_static())
    with pytest.raises(NoiseError):
        handshake.split()
    with pytest.raises(NoiseError):
        handshake.sas_code()


def test_static_public_matches_generated_private_key() -> None:
    key = generate_static()
    handshake = NoiseHandshake(True, key)
    assert handshake.static_public == public_bytes(key)
    assert len(handshake.static_public) == 32
