# DuckTalk

DuckTalk is a direct peer-to-peer, end-to-end encrypted chat application for
two people. It runs in Windows Command Prompt, needs no account, uses no relay
or central message server, and stores no chat history.

## What This Project Provides

### Direct communication

- One-to-one chat over a direct network path between the two peers.
- UDP preferred, with direct TCP as a fallback.
- IPv4 and IPv6 candidate handling.
- Optional STUN discovery for public endpoint detection.
- ICE-style authenticated connectivity checks and NAT hole punching.
- No relay, TURN server, proxy, or central message transport.
- No account registration, presence service, or contact directory.

### Encryption and verification

- Noise XX handshake using X25519, ChaCha20-Poly1305, and SHA-256.
- Fresh per-session static keys and independent send/receive traffic keys.
- Encrypted HELLO and CONFIRM messages before chat is reported as connected.
- Short Authentication String (SAS) shown on both screens for out-of-band
  comparison.
- Quick direct mode: the host approves the named joiner once.
- Full invite mode: both peers approve the SAS and the invite carries the host
  key fingerprint.

### Host-controlled joining

- The host chooses the 10-character join code, or accepts a random suggestion.
- The joiner enters the host IP address and the same code.
- Quick mode asks only the host `Add <name>?`, then starts the chat.
- The host can also set the code non-interactively with
  `ducktalk host --code CODE`.
- Advanced `DTK1-` invites remain available when a direct IP is unsuitable or
  when mutual SAS approval is wanted.

### Privacy and lifecycle

- No chat transcript is written by DuckTalk.
- No message contents appear in diagnostics or logs.
- Messages exist only in memory and in the visible terminal during the session.
- `/clear` clears the visible screen and scrollback.
- `/wipe` clears the terminal and closes the session immediately.
- `/wipe` is best-effort terminal cleanup, not a secure erase of memory, swap,
  crash dumps, or OS-level logs.

### Terminal chat experience

- Color markup such as `<c=blue>hello<c>`.
- Named colors, bright colors, and `#RRGGBB` values.
- Bold, italic, underline, dim, and reverse text.
- ASCII emoticons such as `:smile:`, `:heart:`, `:duck:`, and `:thumbsup:`.
- Raw terminal escape sequences are escaped instead of passed through.
- A menu plus direct `host`, `join`, `diagnose`, and `about` commands.

### Network diagnostics

- Local address discovery.
- STUN mapping checks across multiple servers.
- NAT and CGNAT classification.
- Path and NAT details with `--verbose` or `--debug`.

### Verification and documentation

- 71 automated tests covering invites, STUN, NAT, Noise, UDP/TCP transports,
  direct sessions, CLI behavior, host-chosen codes, and chat formatting.
- Security model, design notes, limitations, and controlled network-test notes
  under `docs/`.

## What It Does Not Provide

- No group chat, file transfer, voice, video, or offline messages.
- No relay or TURN fallback when a direct path cannot be built.
- No anonymity network, metadata protection, or traffic-analysis resistance.
- No long-term identity or key continuity across sessions.
- No guaranteed connection through symmetric NAT, CGNAT, or restrictive
  firewalls.
- No independent security audit. DuckTalk is a from-scratch implementation and
  should not be treated as a replacement for a mature messenger for high-risk
  use.
- No secure erase of memory, terminal scrollback captured elsewhere, crash
  dumps, or operating-system logs.
- No graphical interface; the supported target is Windows Command Prompt.

## Requirements

- Windows 10 or 11 with Command Prompt (`cmd.exe`)
- Python 3.10 or newer
- A network path that permits direct UDP and/or TCP
- Optional but recommended: working IPv6 on both peers

## Install

From the project directory in Command Prompt:

```bat
install.bat
```

Manual install:

```bat
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install .
```

## Quick Start

Start the menu on both machines:

```bat
ducktalk -m
```

### Host

1. Press Enter, or choose **Host direct**.
2. Enter a display name.
3. Choose a join code, or press Enter to accept the suggested random code.
4. Share one printed address and the code with the other person.
5. When the joiner connects, type `y` at `Add <name>?`.

The default port is `47777`. On the same Wi-Fi, share the local address such as
`192.168.100.11:47777`. Internet peers need a reachable public endpoint and
possibly UDP port forwarding.

### Joiner

1. Choose **Join with IP + code or an invite**.
2. Enter the host address (`IP` or `IP:port`) and the join code.
3. Wait for the host to add you. There is no approval prompt on your side.

Chat starts as soon as the host approves. Use `/help` for chat commands.

## Commands

```text
ducktalk -m                     interactive menu
ducktalk host                   host direct; prompt for a join code
ducktalk host --code CODE       host direct with a chosen code
ducktalk host --invite          host and print a full DTK1- invite
ducktalk join [IP[:PORT]]       join direct; prompts for the code
ducktalk join IP --code CODE    join direct non-interactively
ducktalk join DTK1-...          join with a full invite
ducktalk diagnose               STUN/NAT diagnostics
ducktalk about                  security and limitation summary
ducktalk --version
```

Useful options before the subcommand:

```text
--name NAME          display name
--stun HOST:PORT     repeatable; use "none" to disable STUN
--no-udp             disable UDP candidates
--no-tcp             disable direct TCP candidates
--families both|ipv4|ipv6
--port PORT          fixed hosting port (direct default 47777)
--timeout SECONDS    connection timeout
--allow-loopback     include loopback candidates (testing only)
--debug              internal path event logging
--verbose            NAT and path detail logging
```

## Chat Formatting

```text
<c=blue>blue text<c>
<c=red>red<c>  <c=green>green<c>  <c=yellow>yellow<c>
<b>bold</b>  <i>italic</i>  <u>underline</u>  <dim>dim</dim>  <rev>reverse</rev>
:smile:  :heart:  :duck:  :fire:  :thumbsup:
```

Colors include `black`, `red`, `green`, `yellow`, `blue`, `magenta`, `cyan`,
`white`, `gray`, bright variants, `orange`, `purple`, `pink`, `lime`, `teal`,
`gold`, and `#RRGGBB` hex values. `<c>` or `</c>` closes the current color.

The sender sees raw markup because Command Prompt echoes typed input; the peer
sees the rendered text. Both peers need a version that supports formatting.
Unknown tags remain literal. Use `/clear` to clear the screen or `/wipe` to
clear everything and close the session.

## Security Notes

- Message content is encrypted end to end; network observers see encrypted
  traffic, endpoints, timing, and approximate sizes.
- The join code is a bearer secret. Share it privately and choose a
  random-looking code rather than a name or date.
- Quick direct mode relies on host approval plus optional SAS comparison. Full
  invite mode requires mutual SAS approval.
- `/wipe` removes the visible terminal transcript on a best-effort basis. It
  does not defeat screen recording, malware, memory forensics, or OS logs.

## Documentation

- [Security model](docs/SECURITY.md)
- [Design](docs/DESIGN.md)
- [Limitations](docs/LIMITATIONS.md)
- [Network tests](docs/NETWORK_TESTS.md)
