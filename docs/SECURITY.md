# DuckTalk security model

DuckTalk is an unverified, from-scratch implementation. It uses well-known
protocol designs and the maintained `cryptography` library, but it has not been
independently audited and must not be treated as a replacement for a mature
messenger when the consequences of failure are high.

## What DuckTalk protects

- Chat message content is encrypted end to end with ChaCha20-Poly1305.
- Both peers prove possession of their per-session X25519 static keys in a
  Noise XX handshake.
- The handshake transcript is bound to the session ID and both display names.
- An 8-digit SAS is displayed on both screens so the two people can detect an
  active man-in-the-middle when they compare it.
- In full invite mode, chat is enabled only after both users approve the SAS.
  In quick direct mode, the host approves the named peer once and the joiner
  auto-accepts after code-authenticated PEER_INFO; both sides still exchange
  encrypted confirmations.
- Chat messages are not written to disk by DuckTalk and are not included in
  diagnostics.
- Chat display markup is parsed locally. Only known color/style tags produce
  ANSI output; raw terminal control characters are escaped, and unknown tags
  remain literal text. `/wipe` clears the visible terminal buffer on a
  best-effort basis.
- In direct mode, control messages and STUN checks are authenticated with a
  token derived from the short join code.
- Unused candidate paths are closed after a session is secured.

## What DuckTalk does not protect

- **A replaced or guessed join code.** Anyone who obtains the join code can
  attempt to contact the host. The host still has to approve the named peer.
  A host-chosen code is convenient but can be much weaker than a random one;
  use 10 random-looking characters, not a name, date, or repeated pattern.
  Direct mode does not pin the host key in advance, so the SAS is displayed on
  both screens for active-MITM detection; in quick direct mode only the host is
  prompted, which is a deliberate usability tradeoff. The advanced invite
  carries a host-key fingerprint that can be verified separately.
- **A compromised endpoint.** Malware, a keylogger, a compromised terminal, a
  debugger, or a person looking at the screen can read messages. Terminal
  scrollback, screen recordings, and crash dumps may retain text even after
  `/clear` or `/wipe`.
- **Traffic analysis.** An observer can see that two addresses are talking, how
  much encrypted data is sent, when it is sent, and which STUN servers were used.
- **Denial of service.** An on-path attacker can drop, delay, replay, or forge
  unauthenticated packets. Authenticated control messages can also be replayed;
  an attacker without the invite token cannot create new valid ones.
- **Availability through restrictive NATs.** There is no relay and no TURN
  fallback. Symmetric NAT, carrier-grade NAT, restrictive firewalls, and some
  corporate networks can prevent a direct path.
- **Long-term identity.** Static keys are generated fresh for every process
  session. DuckTalk cannot recognise a peer from a previous conversation.
- **Post-compromise security.** There is no rekeying during a session.

## Protocol flow

1. In direct mode the host chooses a 10-character join code, or accepts a
   random suggestion, and derives the 128-bit session ID and token from it. In advanced invite mode it creates a
   random session ID and token. Either way it creates a fresh X25519 static key.
   The advanced invite also carries the host static public key, display name,
   creation/expiry data, and candidates.
2. The joiner generates its own fresh static key and sends an authenticated
   CONNECT over candidate paths. The host creates a pending request.
3. The joiner starts ICE-style checks as soon as it has the invite. In quick
   direct mode both sides auto-accept the transport request and the host
   approves once after the SAS is derived; in full invite mode both users
   approve the incoming peer before the host runs checks. STUN binding requests
   use the session ID in the username and the invite token as the short-term
   credential, so checks are authenticated with HMAC-SHA1.
4. The host selects a working pair, sends an authenticated SELECT, and the two
   sides run `Noise_XX_25519_ChaChaPoly_SHA256` over that path. The prologue is
   `DuckTalk/1`, the session ID, and both names.
5. Each side pins the static key it expects: the host uses the joiner key from
   CONNECT. In advanced invite mode the joiner uses the host key from the
   invite; in direct mode it uses the host key from HMAC-authenticated
   PEER_INFO. A mismatch aborts.
6. Noise `split()` derives independent send and receive keys. Each side sends an
   encrypted HELLO; receiving the peer's HELLO confirms that the peer has the
   same traffic keys.
7. Both sides derive the SAS from the final handshake hash and both static
   public keys. Both screens display it. In quick direct mode the joiner
   auto-accepts and the host approves once; in full invite mode both users
   compare and approve.
8. After approval, each side sends an encrypted CONFIRM. The session is
   reported connected only when the peer's CONFIRM arrives.
9. All unused UDP/TCP paths are closed. Chat frames use counter-based nonces,
   ChaCha20-Poly1305, and direction-specific keys.

## Join codes, invites, and control messages

A direct join code is a bearer secret. It deterministically derives the session
ID and token:

```text
SHA-256("DuckTalk/quick/v1\0" || code)
```

The code is 10 characters from an unambiguous alphabet, roughly 49 bits of
entropy when generated randomly. A host-chosen code can have much less entropy.
Anyone who obtains it can attempt to contact the host; the host still has to
approve the named peer. The SAS is shown on both screens for optional
comparison in quick direct mode. There is no server-side rate limit or lockout.
Use a trusted channel to share it.

An advanced invite is also a bearer secret:

```text
DTK1-<base64url(canonical JSON)>
```

It contains no chat content. Anyone who possesses it can attempt to contact the
host and will be shown to the host as an incoming request. In full invite mode
both users must still approve the request and the SAS must match.

Control messages (CONNECT, PEER_INFO, READY, SELECT, REJECT) are authenticated
with HMAC-SHA256 using the session token over canonical JSON. In direct mode the
token is derived from the join code; in advanced mode it is carried in the
invite. The token is not sent inside control messages. An on-path observer therefore cannot learn the
token from traffic and cannot forge a valid control message without it. The
token can still be replayed if observed, so control messages are not a
confidentiality mechanism; message content remains protected by Noise.

Noise handshake messages are not covered by that HMAC. They are authenticated
by Noise itself and are rejected if the handshake transcript does not match.

## SAS

The SAS is:

```text
SHA-256("DuckTalk SAS v1\0" || handshake_hash || initiator_static || responder_static)
```

The first 5 bytes are reduced modulo 100,000,000 and printed as two groups of
four digits. It binds the full Noise transcript and both static keys. Because it
is only 8 digits, an active attacker has a 1 in 100,000,000 chance per attempt
of producing a matching code. In full invite mode both users must compare the
codes and approve. In quick direct mode both screens display the SAS, but only
the host is prompted; compare it out of band if you need active-MITM detection.

If the host rejects the SAS, DuckTalk raises `SessionAborted`, closes the path,
and does not try another candidate. A failed SAS check is a security event, not
a connectivity failure.

## Transport details

- UDP chat is a small reliable layer over encrypted datagrams: sequence
  numbers, acknowledgements, retransmission, a receive window, and duplicate
  suppression. Replay of old counters is rejected.
- TCP chat uses length-prefixed encrypted frames over the ordered stream.
- Heartbeats run every 10 seconds and a peer is considered gone after 40
  seconds without traffic.
- Chat text is limited to 900 UTF-8 bytes. Chat is displayed with non-printable
  characters escaped.
- No diagnostic output includes message text, the invite token, or traffic keys.

## Cryptographic primitives

- X25519 for ephemeral and static Diffie-Hellman
- ChaCha20-Poly1305 for handshake and transport encryption
- SHA-256 for the Noise hash and SAS
- HMAC-SHA256 for Noise HKDF and control-message authentication
- HMAC-SHA1 for STUN MESSAGE-INTEGRITY (required by the STUN format)

The Noise implementation follows revision 34 of the specification for the
`XX` pattern. It was written for this project and is covered by unit tests for
the normal exchange, tampering, and key agreement. That is not a formal
verification.

## Reporting a problem

This is a local, unsigned project. Do not use it for sensitive production
traffic until it has been independently reviewed.
