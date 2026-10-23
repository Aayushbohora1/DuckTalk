### Advanced direct-connectivity engineering for DuckTalk V1

Implement the most reliable standards-based direct P2P connectivity architecture possible, inspired by techniques used in secure P2P networking applications.

Mandatory constraints:
- No relay servers.
- No centralized message transport.
- No hidden proxying.
- No chat-history storage.
- No unauthorized firewall bypasses or stealth networking.

Implement and test the following:

1. ICE connectivity checks with prioritized address candidates.
2. STUN discovery of public-facing IP addresses and ports.
3. UDP hole punching, with coordinated simultaneous connectivity checks.
4. Direct IPv6 connectivity when both peers have usable IPv6 connectivity.
5. Direct TCP connectivity when supported and appropriate.
6. Candidate exchange through manually shared connection information or an explicitly documented, user-controlled signaling channel that carries no chat messages.
7. Cryptographically authenticated handshakes before any chat begins.
8. Strong end-to-end encryption using an established protocol and maintained implementation.
9. Clear diagnostics for symmetric NAT, CGNAT, restrictive firewalls, unreachable peers, and failed candidate pairs.
10. Automatic retry and selection among viable direct connection candidates.

Do not attempt to bypass network security controls or claim universal success. Never introduce a relay as a fallback.

For peer discovery, provide manual IP/port exchange as a fully decentralized option. Explain that automated discovery between strangers requires some way to exchange peer information.

Write automated tests and conduct controlled network tests where possible. Report which NAT configurations were actually tested and which remain unverified.

The application must never report a direct connection unless the actual peer-to-peer transport and authenticated encrypted session have been established.

Maintain the existing `ducktalk -m` menu, incoming requests, mutual approval, one-command installation, and zero-chat-history requirements.