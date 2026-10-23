# Network test report

Date: 2026-10-23

This report records what was actually exercised. It is not a claim that DuckTalk
works on every network. In particular, no two-machine Internet session, no
symmetric NAT, no CGNAT, and no real IPv6 Internet path were tested.

## Environment

- Windows, Command Prompt (`cmd.exe`)
- Python 3.14.4 in the project virtual environment
- `cryptography` 50.0.2
- IPv4 LAN address: `192.168.100.11`
- Public IPv4 mapping: stable across the three STUN servers, address redacted
- IPv6: no local global IPv6 address; name resolution for the STUN hosts failed
  with `[Errno 11004] getaddrinfo failed`

## Automated tests

Command:

```bat
.venv\Scripts\python.exe -m pytest -q
```

Result: **71 passed**.

Coverage relevant to networking and the security boundary:

- Invite encoding/decoding, malformed and oversized candidate lists, expiry,
  candidate limits, and address parsing.
- STUN encode/decode, XOR-MAPPED-ADDRESS, MESSAGE-INTEGRITY, FINGERPRINT, and
  discovery against a local fake STUN server.
- NAT classification logic, including private, public, CGNAT, and missing
  observations. Note: Python 3.14 treats the TEST-NET documentation ranges as
  private, so those tests use real public addresses.
- Noise XX initiator/responder agreement, transport key split, tampered
  handshake rejection, and SAS agreement.
- Reliable UDP channel: ordered delivery, ACKs, retransmission, duplicate
  suppression, and close handling.
- TCP secure channel: framing, encryption, heartbeat, and close handling.
- Connectivity-check manager: priorities, success selection, failure handling.
- Session end-to-end:
  - IPv4 UDP over loopback
  - IPv4 direct TCP over loopback
  - IPv6 UDP over `::1`
  - direct IP + join-code mode over IPv4 UDP and TCP
  - SAS rejection raises `SessionAborted` and does not connect
  - a mismatched expected peer static key is rejected
  - control messages are HMAC-authenticated and do not expose the session token
- Direct address parsing, quick-code normalization/derivation, direct invites,
  host-chosen code parsing and prompt behavior, CLI parsing, menu handling, and
  non-interactive paths.
- Chat formatting: color open/close and nesting, unclosed-tag reset, bold/
  italic/underline styles, hex colors, ASCII emoticons, plain-text fallback,
  unknown tags, and escaping raw terminal control characters.

### What these tests do not prove

Loopback tests bypass NAT, firewalls, interface routing, packet loss, and real
timing. They prove that the protocol and framing work when packets arrive, not
that a path can be established on a hostile or restrictive network.

## Installed CLI end-to-end test

After `pip install .`, two installed `ducktalk` processes were run on the same
machine with `--stun none --allow-loopback --families ipv4`:

- The host printed an invite and waited.
- The joiner used the invite and both approval prompts were answered `y`.
- Both processes displayed the same SAS: `1554 8214`.
- The host received `hello from joiner` over the direct UDP path while its chat
  prompt was active.
- Both processes exited on `/quit`.
- The working directory was a fresh temporary directory. It remained empty, so
  this test wrote no chat transcript or other files.

The host first received the request over direct TCP and then secured the
session over UDP, which also exercised the mixed-path transition.

## Host-only approval test

The quick direct flow was run with two real CLI processes. The joiner entered
the host address and code and received no approval prompt. The host received one
`Add Joiner?` prompt, typed `y`, and both sides entered chat. Messages were
exchanged in both directions and both processes exited cleanly. This verifies
the simplified host-only approval path; it still used one machine.

## Host-chosen join code test

The host-set code path was run with two real CLI processes, from a temporary
working directory:

```bat
ducktalk --name Host --stun none --allow-loopback --families ipv4 --port 47888 host --code ABCDE-FGHJK
ducktalk --name Join --stun none --allow-loopback --families ipv4 join 127.0.0.1:47888 --code ABCDE-FGHJK
```

The host printed `Join code: ABCDE-FGHJK`; the joiner received no approval
prompt; the host received one `Add Join?` prompt, typed `y`, and both sides
entered chat. Both displayed SAS `3835 1731` and exited after `/quit`. This
validates that a host-chosen code is used consistently by both sides; it still
used one physical machine.

The interactive prompt was also tested without `--code`. An invalid short code
was rejected, the prompt re-asked, and a valid custom code started the host
with that code displayed.

## Direct IP + code CLI test

Two local CLI processes were run with `--stun none --allow-loopback --families
ipv4`:

```bat
ducktalk --name Host --port 47777 host
ducktalk --name Join join 127.0.0.1 --code <code>
```

The host printed `127.0.0.1:47777` and a 10-character join code. The host
approval prompt was answered `y`; the joiner had no approval prompt; both sides
displayed SAS `9876 3586`; the host received `hello from joiner` over UDP; both
processes exited cleanly on `/quit`. This validates the direct signalling path,
not Internet reachability. The join code was not recorded in this report.

The same direct flow was repeated with the installed user-site wheel, run from
an empty temporary directory. Both sides displayed SAS `6097 2722`, the
message arrived, both processes exited with code 0, and the directory remained
empty. A second installed run joined the machine's LAN address
`192.168.100.11:47777`; both sides displayed SAS `4617 8540` and exited cleanly.
This still used one physical machine, so it does not prove two-host LAN
reachability.

## Hosted wheel install test

The project was built into `dist\ducktalk-1.0.0-py3-none-any.whl` and served
over a local HTTP server. `install-ducktalk.cmd` downloaded the wheel with
`curl.exe`, installed it with `pip --user` into an isolated `PYTHONUSERBASE`,
and `py -3 -m ducktalk --version` printed `DuckTalk 1.0.0`. The same test was
run with a `file://` URL. The updated installer also adds the user Scripts
folder to PATH; `ducktalk -m` was then run successfully from a separate working
directory. This validates the download-and-install path, not a real remote
host, HTTPS certificate handling, or a clean machine without Python.

## Live STUN diagnostic

Command:

```bat
.venv\Scripts\python.exe -m ducktalk --stun-timeout 2 diagnose
```

Observed:

```text
IPv4 local addresses: 192.168.100.11
IPv6 local addresses: none
IPv4 UDP socket 192.168.100.11:51283
  stun.l.google.com:19302: mapping <redacted>:63837  RTT 93 ms
  stun.cloudflare.com:3478: mapping <redacted>:63837  RTT 19 ms
  stun.nextcloud.com:443: mapping <redacted>:63837  RTT 370 ms
  assessment: NAT present
IPv6 UDP socket None:52783
  all three servers: network error [Errno 11004] getaddrinfo failed
  assessment: No STUN response: UDP blocked, firewalled, or offline
```

Interpretation:

- The three servers returned the **same public IPv4 address and port** for the
  same local UDP socket. That is consistent with endpoint-independent mapping,
  but it is not proof: reachability by a real peer was not tested.
- A NAT is present because the local address differs from the mapped address.
- The machine has no usable IPv6 path to the public STUN servers.
- STUN cannot test TCP inbound reachability. No TCP reachability test was
  possible without a peer.

## Tested configurations

| Configuration | Transport | Result |
| --- | --- | --- |
| Two endpoints, same machine, IPv4 loopback | UDP | Session established, chat round trip |
| Two endpoints, same machine, IPv4 loopback | TCP | Session established, chat round trip |
| Two endpoints, same machine, IPv6 `::1` | UDP | Session established, chat round trip |
| Two installed CLI processes, IPv4 loopback | UDP after initial TCP | SAS matched, chat delivered, no files written |
| Two CLI processes, direct IP + code, IPv4 loopback | UDP | SAS matched, chat delivered, clean exit |
| Two installed CLI processes, direct LAN address, same machine | UDP | SAS matched, chat delivered, clean exit |
| Local fake STUN server | UDP | Discovery and mapping parsed |
| Live STUN, IPv4 NAT | UDP | Stable mapping from three servers |
| Live STUN, IPv6 | UDP | No IPv6 connectivity |
| SAS mismatch | UDP | Aborted, no session |
| Expected static key mismatch | UDP | Aborted, no session |

## Untested configurations

These are the important gaps. None of them should be described as working.

- Two physical machines on the same LAN (the direct IP + code flow was tested
  only on one machine over loopback)
- Two peers behind different home routers (NAT-to-NAT)
- Symmetric NAT on either side
- Carrier-grade NAT (CGNAT)
- Double NAT
- Port-restricted cone NAT
- Address-restricted cone NAT
- Corporate firewalls and UDP-blocked networks
- TCP inbound through a NAT or firewall
- Public IPv6 between two hosts
- Mobile networks and Wi-Fi hand-offs
- Packet loss, high latency, reordering, and jitter beyond loopback
- Long-running sessions and heartbeat behaviour over a real idle path
- STUN server failure during candidate gathering
- Multiple interfaces, VPNs, and split tunnelling
- IPv4/IPv6 dual-stack fallback on real networks

## How to add a real-network result

Run `ducktalk diagnose` on both peers and record:

1. Local addresses and families.
2. STUN mappings and whether they are stable across servers.
3. NAT assessment.
4. Whether a host/join session succeeded, and over which protocol and candidate
   types.
5. Whether the SAS matched.
6. Any firewall or router configuration used.
7. The failure text and `--verbose` path report if it did not work.

Do not record chat contents, invite tokens, or private keys in a test report.
