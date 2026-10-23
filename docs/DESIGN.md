# DuckTalk design

DuckTalk is a terminal chat program with a direct peer-to-peer data path. It
does not use HTTP, WebSocket, a rendezvous server, or a relay. This document
describes the moving parts and the important timing rules.

## Modules

| Module | Responsibility |
| --- | --- |
| `candidates.py` | Candidate model, priorities, local address gathering, invite codec |
| `stun.py` | STUN binding request/response, XOR-MAPPED-ADDRESS, integrity, fingerprint |
| `checks.py` | ICE-style authenticated connectivity checks |
| `transport.py` | UDP endpoint, reliable UDP secure channel, direct TCP secure channel |
| `paths.py` | Path abstraction, UDP/TCP framing, Noise message routing, path buffers |
| `noise.py` | Noise XX handshake, transport keys, SAS |
| `nat.py` | NAT/CGNAT classification and diagnostic summaries |
| `session.py` | Host/join state machines, approval, candidate selection, lockdown |
| `cli.py` | Argument parsing, menu, prompts, chat loop, diagnostics |
| `formatting.py` | ANSI colors, text styles, ASCII emoticons, terminal cleanup |

## Host startup

Direct mode is the default:

1. Generate a fresh X25519 static key.
2. Use the 10-character join code chosen by the host with `host --code`, or
   prompt for one and offer a random suggestion. A host-set code is normalized
   to the DuckTalk alphabet and rejected if it is the wrong length.
3. Derive the 128-bit session ID and control/STUN token from the join code with
   domain-separated SHA-256.
4. Open one UDP socket per enabled family and bind it to a fixed port (47777 by
   default). If that port is unavailable, fall back to an ephemeral port and
   display the actual port.
5. Build host and optional STUN server-reflexive UDP candidates.
6. Open a TCP listener, preferably on the same port as UDP, for direct fallback.
7. Display the local/public endpoints and the join code. No full invite is
   needed for direct mode.

The advanced invite mode instead generates random session ID and token values
and prints a `DTK1-` invite with the host static public key. Both modes use the
same host/join state machines after setup. There is no server registration and
no keepalive to a third party.

## Join startup

Direct mode:

1. Parse an `IP` or `IP:port` target and normalize the join code.
2. Derive the same session ID and token as the host.
3. Create a synthetic direct invite containing that endpoint as a UDP
   candidate and, unless disabled, a TCP candidate on the same port.
4. Generate a fresh X25519 static key and UDP sockets.
5. Send CONNECT repeatedly to the direct candidate. The same authenticated
   CONNECT is also sent over direct TCP.
6. Wait for PEER_INFO (host accepted) or REJECT.
7. The direct invite has no pinned host static key, so the host key carried in
   the HMAC-authenticated PEER_INFO is used for the Noise pin. The SAS is shown
   on both screens.
8. In quick direct mode the joiner auto-accepts the incoming peer, sends READY,
   stops the connect burst, and waits for SELECT. The host approves once after
   the SAS is derived. Full invite mode asks both users to approve.

Advanced invite mode additionally validates the invite prefix, size, expiry,
candidate count, protocols, address families, key length, host name, and pinned
host static key.

## Candidate and pair selection

Candidate priority follows an ICE-like formula:

```text
(type_preference << 24) | (local_preference << 8) | (256 - component)
```

- Host candidates: 126
- Peer-reflexive: 110
- Server-reflexive: 100
- Relay: never accepted
- IPv6 is preferred over IPv4 by one local-preference point
- Loopback has the lowest local preference
- UDP is preferred over TCP by component ordering

The host is the controlling agent. STUN checks carry the session username and
are authenticated with the invite token as the short-term credential. The
joiner starts sending checks to the invite candidates as soon as it has the
invite, and the host sends checks to every UDP candidate plus the joiner's
observed source address after accepting the request. Both directions therefore
create NAT bindings while the host selects. A successful check yields a pair;
the host waits for at least one success and a short settle window, then tries
successful pairs in priority/RTT order.

The host sends SELECT for the chosen pair and waits for the joiner's first Noise
message. If all UDP pairs fail, the host tries live direct TCP connections. If
neither works, the session fails with diagnostics. There is no relay fallback.

## Handshake and approval

```text
joiner                                   host
  | CONNECT (HMAC token)                   |
  |--------------------------------------->|
  |                                        | quick direct: auto-accept
  | PEER_INFO (HMAC token)                  | full invite: user approves
  |<---------------------------------------|
  | quick direct: auto-accept              |
  | full invite: user approves             |
  | READY (HMAC token)                      |
  |--------------------------------------->|
  |                                        | ICE checks, SELECT
  |<--------------------------------------->|
  | Noise XX msg1                          |
  |--------------------------------------->|
  | Noise XX msg2                          |
  |<---------------------------------------|
  | Noise XX msg3                          |
  |--------------------------------------->|
  | encrypted HELLO                        |
  |<--------------------------------------->|
  | SAS displayed on both screens
  | quick direct: host approves once
  | full invite: both users approve
  | encrypted CONFIRM                      |
  |<--------------------------------------->|
  | chat                                   |
```

The joiner never sends HELLO or chat before it has validated PEER_INFO. In
full invite mode the local user also approves the peer before READY. The host
never starts Noise before accepting the request. In quick direct mode the host
accepts the transport automatically and makes the single approval decision at
the SAS stage. Both sides pin the static key they expect in the handshake.

## Reliability

UDP uses a small reliable layer:

- Each encrypted packet carries a direction-specific counter nonce.
- Data, HELLO, BYE, and CONFIRM are acknowledged and retransmitted.
- A receive window suppresses duplicates and old counters.
- PING frames keep NAT bindings alive every 10 seconds.
- A peer silent for 40 seconds is considered gone.

TCP is already ordered and reliable; it uses length-prefixed encrypted frames
and the same heartbeat timeout. Both channels finish with a BYE and close the
socket.

## Lockdown

After host approval (or mutual approval in full invite mode):

- Every UDP path and TCP path except the selected one is closed.
- The selected path remains the only transport.
- Chat frames are the only accepted application frames.
- Chat text is capped at 900 UTF-8 bytes and rendered with control characters
  escaped.

## Timeouts

Defaults are intentionally conservative:

| Setting | Default |
| --- | --- |
| STUN per-server | 1.2 s |
| CONNECT / PEER_INFO | 30 s |
| Host UDP settle | 6 s |
| Hopeful pair handshake | 15 s |
| SAS approval window | 120 s |
| Invite lifetime | 3600 s |

The CLI multiplies the host request and session timeout to give a person time to
paste an invite and approve prompts. Validation should always use explicit
smaller timeouts.

## Direct code and invite format

The direct code is 10 characters from an unambiguous base32-like alphabet. The
session ID and token are derived as:

```text
SHA-256("DuckTalk/quick/v1\0" || code)
  first 16 bytes  -> session ID
  second 16 bytes -> control and STUN token
```

The code is a bearer secret. It is not a password hash and has no server-side
rate limit; the host approval is mandatory, and the SAS is displayed on both
screens for optional comparison. Full invite mode requires mutual SAS approval.

The advanced invite is `DTK1-` followed by unpadded base64url of canonical JSON.
The fields include:

- `v`: format version
- `sid`: session ID (base64url)
- `token`: invite token (base64url)
- `name`: sanitized host name
- `static`: host X25519 public key
- `candidates`: up to 32 candidate objects
- `created`, `expires`: Unix timestamps

The invite contains no messages and no private key. It is a bearer credential
for contacting the host; full invite mode still requires approval and a matching
SAS from both users. Direct mode sends no full invite at all: the address and
code are the signalling channel.

## Failure behaviour

- A rejected incoming request sends REJECT to the peer and returns to waiting.
- A host SAS rejection raises `SessionAborted`, closes the selected path, and
  does not try other candidates. A SAS mismatch is a security failure.
- A failed candidate pair is recorded and the host tries the next successful
  pair, then direct TCP.
- A closed control path wakes waits immediately with `session closed`.
- All failures are reported as `DirectConnectError` with endpoint/path details
  and no chat content.
