# Limitations

DuckTalk deliberately has no relay, no central server, and no hidden proxy. The
cost of that design is that some networks cannot be traversed. The following
limits are intentional and should be treated as part of the product, not as
bugs to be worked around with a relay.

## Connectivity

- **Symmetric NAT** is not reliably traversable. A new mapping per destination
  means the address observed by STUN is not the address needed by the peer.
- **Carrier-grade NAT (CGNAT)** often prevents inbound UDP and TCP. A public
  address reported by STUN does not imply that the address is reachable.
- **Restrictive firewalls** may block UDP entirely, block inbound TCP, or allow
  traffic only through an HTTP proxy. DuckTalk does not use proxies.
- **TCP behind NAT** requires an inbound port mapping or a permissive firewall.
  DuckTalk's TCP listener is direct; it is not a relayed TCP connection.
- **Port-restricted and address-restricted NATs** may work, but success depends
  on the exact mapping and filtering behaviour and on both peers sending at the
  right time. The current check logic is an ICE-style subset, not full ICE.
- **No port prediction** and **no birthday-paradox port scanning** are used.
- **IPv6** must be available on both peers and must permit the chosen UDP/TCP
  flow. The presence of a global IPv6 address does not guarantee reachability.
- **STUN is optional but recommended.** Without STUN, only local host candidates
  are advertised, which is normally useful only on the same LAN. The public
  address shown by STUN does not prove inbound reachability.
- **STUN blocking** prevents discovery of the public mapping. DuckTalk then has
  only host candidates and will usually fail across NAT.
- **One direct path is used per session.** There is no mid-session migration to
  another interface or address.

## Signalling

- The host's IP address and join code must be exchanged manually over some
  other channel. DuckTalk does not provide discovery, accounts, presence, or a
  directory.
- The join code is a bearer secret. Anyone who sees it can attempt a connection;
  the host still has to approve. The host can choose the code; a weak choice is
  easier to guess, so use 10 random-looking characters rather than a name or
  date. The SAS is shown on both screens for optional comparison in quick
  direct mode; full invite mode requires mutual approval. There is no
  server-side rate limit or lockout.
- The default direct port is `47777`. If it is already in use, DuckTalk falls
  back to an ephemeral port and displays the actual `IP:port` to share. A
  firewall or router must permit that port for Internet peers; this is still a
  direct connection, not a relay.
- Direct mode does not pin the host static key in advance. It relies on the
  join code to authenticate PEER_INFO and on host approval. The SAS is displayed
  on both screens, but quick direct mode prompts only the host; compare the SAS
  out of band if you need active-MITM detection. Use full invite mode for mutual
  SAS approval and a host-key fingerprint.
- Advanced invites must be exchanged manually over some other channel. They
  expire after one hour by default; a clock-skewed peer may reject an otherwise
  valid invite. They include endpoint addresses, so share them only with the
  intended peer and over a channel you trust.
- If an attacker replaces the invite, the victim can be connected to the
  attacker. The SAS will match that attacker. Host-key fingerprint verification
  or an in-person exchange is required for higher assurance.

## Chat

- Text only, one peer per session, one session per process.
- No file transfer, voice, video, group chat, or offline messages.
- Messages are best-effort while the path is alive. UDP retransmits for a
  limited time; a dead path ends the session instead of holding messages.
- Chat messages are limited to 900 UTF-8 bytes.
- No chat history exists by design. Closing the session loses the conversation.
- DuckTalk does not write a transcript, but the operating system may swap
  memory, keep a crash dump, or preserve terminal scrollback. Those are outside
  DuckTalk's control.
- The terminal may still be captured by screen recording, accessibility tools,
  or a compromised shell. DuckTalk cannot defend a compromised endpoint.
- Colors require a terminal with ANSI/VT support. If it is unavailable,
  recognized markup is stripped and the chat remains readable in plain text.
- Emoji support is intentionally ASCII-only; Unicode emoji depends on the
  console font and is not guaranteed.
- `/clear` and `/wipe` are best-effort terminal cleanup. They do not erase
  Windows console history, crash dumps, memory, swap, or a recording.

## Security

- The Noise implementation is custom code using maintained primitives. It is
  not a third-party audited Noise library.
- There is no formal verification, no independent audit, and no bug bounty.
- There is no long-term identity, no key continuity, and no way to recognise a
  peer across sessions except by comparing a fresh SAS every time (and quick
  direct mode does not require that comparison).
- There is no message padding. Message sizes and timing are visible to an
  observer.
- There is no deniability protocol, no anonymity network, and no metadata
  protection.
- There is no protection against a malicious peer who records the conversation
  at the endpoint.
- The invite token protects control messages, but it is a shared bearer secret.
  It is not a substitute for verifying the SAS when active-MITM protection is
  required.
- An active on-path attacker can always deny service by dropping packets.

## Platform

- Windows Command Prompt (`cmd.exe`) is the supported and tested platform.
  The code is pure Python and uses standard sockets, so it may run elsewhere,
  but no other platform or installer is documented here.
- IPv6 and multiple network interfaces are handled opportunistically; complex
  interface routing and VPN split tunnels are not specifically modelled.
- The tool is a terminal application. It does not run in a browser and does not
  provide a graphical interface.

## What has actually been tested

See [NETWORK_TESTS.md](NETWORK_TESTS.md). Local loopback tests and one live STUN
diagnostic do not establish that DuckTalk traverses real NATs, firewalls, CGNAT,
or the public IPv6 Internet.
