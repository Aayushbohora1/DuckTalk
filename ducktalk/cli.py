"""Command line interface and the interactive `ducktalk -m` menu."""

from __future__ import annotations

import argparse
import getpass
import queue
import threading
import time

from . import __version__
from .candidates import (
    DEFAULT_DIRECT_PORT,
    Invite,
    InviteError,
    format_endpoint,
    format_quick_code,
    gather_host_addresses,
    new_quick_code,
    normalize_quick_code,
    parse_endpoint,
    peer_fingerprint,
)
from .formatting import clear_screen, enable_ansi, format_chat
from .nat import NatProfile
from .session import (
    Callbacks,
    DirectConnectError,
    HostSession,
    IncomingInfo,
    JoinSession,
    SecureSession,
    SessionConfig,
)
from .stun import DEFAULT_STUN_SERVERS, stun_discover_on_socket
from .transport import UdpEndpoint

PRINT_LOCK = threading.Lock()
STDIN_CLOSED = False


def say(text: str = "") -> None:
    with PRINT_LOCK:
        print(text, flush=True)


def ask(prompt: str) -> str:
    global STDIN_CLOSED
    try:
        return input(prompt)
    except EOFError:
        STDIN_CLOSED = True
        return ""


def ask_yes(prompt: str, *, default: bool = False) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    while True:
        answer = ask(prompt + suffix).strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        say("Please answer y or n.")


def default_name() -> str:
    try:
        name = getpass.getuser()
    except Exception:
        name = "peer"
    return name.strip() or "peer"


class Console:
    def __init__(self) -> None:
        self.peer = "peer"

    def incoming(self, info: IncomingInfo) -> bool:
        say("")
        say("Incoming direct session request")
        say(f"  {info.summary()}")
        say(f"  Candidates offered: {info.candidate_count}")
        if info.response:
            say("  The host accepted your request; confirm you trust this peer.")
        else:
            say("  No relay is used. The session starts only if both sides approve.")
        return ask_yes("Approve this peer?", default=False)

    def _show_sas(self, sas: str, peer: str) -> None:
        say("")
        say("=" * 48)
        say(f"  VERIFY THIS CODE WITH {peer.upper()}")
        say(f"  SAS: {sas}")
        say("=" * 48)
        say("  Read it out loud or compare it over a separate trusted channel.")
        say("  If the codes differ, a man-in-the-middle is present: reject.")

    def sas(self, sas: str, peer: str) -> bool:
        self._show_sas(sas, peer)
        return ask_yes("Do both screens show exactly this code?", default=False)

    def accept_sas(self, sas: str, peer: str) -> bool:
        self._show_sas(sas, peer)
        say(f"Waiting for {peer} to add you...")
        return True

    def add_peer(self, sas: str, peer: str) -> bool:
        self._show_sas(sas, peer)
        return ask_yes(f"Add {peer}?", default=False)


def choose_quick_code(default: str) -> str:
    while True:
        answer = ask(f"Choose a join code [{format_quick_code(default)}]: ").strip()
        if not answer:
            return default
        try:
            return normalize_quick_code(answer)
        except InviteError as exc:
            say(f"Invalid join code: {exc}")


def build_config(
    args: argparse.Namespace,
    name: str,
    *,
    quick_code: str = "",
    port: int = 0,
) -> SessionConfig:
    servers = args.stun
    if servers is None:
        servers = list(DEFAULT_STUN_SERVERS)
    cleaned: list[str] = []
    for server in servers:
        for part in str(server).split(","):
            part = part.strip()
            if part and part.lower() != "none":
                cleaned.append(part)
    families = {"both": (4, 6), "ipv4": (4,), "ipv6": (6,)}[args.families]
    return SessionConfig(
        name=name,
        stun_servers=tuple(cleaned),
        allow_loopback=args.allow_loopback,
        enable_udp=not args.no_udp,
        enable_tcp=not args.no_tcp,
        families=families,
        stun_timeout=args.stun_timeout,
        connect_timeout=args.timeout,
        select_timeout=max(10.0, args.timeout),
        noise_timeout=max(10.0, args.timeout),
        debug=args.debug,
        port=port,
        quick_code=quick_code,
    )


def safe_text(text: str) -> str:
    return "".join(ch if ch.isprintable() else f"\\x{ord(ch):02x}" for ch in text)


def print_error(exc: BaseException) -> None:
    say(f"Error: {safe_text(str(exc))}")
    details = getattr(exc, "details", None)
    if details:
        say("Diagnostics:")
        for line in details:
            say("  " + line)


def show_host_endpoints(host: HostSession) -> None:
    say("Direct host is listening. No relay is in use.")
    say("")
    local = host.local_endpoints()
    if local:
        say("Your address(es):")
        for protocol, address, port in local:
            say(f"  {format_endpoint(address, port)}  ({protocol.upper()})")
    else:
        say("Your address: unavailable (check your network connection).")
    public = host.public_endpoints()
    if public:
        say("")
        say("Public address(es) seen by STUN (may require port forwarding):")
        for protocol, address, port in public:
            say(f"  {format_endpoint(address, port)}  ({protocol.upper()})")
    if host.config.quick_code:
        say("")
        say(f"Join code: {format_quick_code(host.config.quick_code)}")
        say("Give a friend one address above and this code.")
        say("The code is a shared secret. Share it privately.")
    say("")


def show_connected(session: SecureSession) -> None:
    say("")
    say(f"You are {session.local_name}. Connected directly to {session.peer_name} over {session.transport}.")
    say(f"Remote endpoint: {session.remote}")
    say(f"Authenticated SAS: {session.sas}")
    say("End-to-end encrypted. No relay is in use. Messages are not stored.")
    say("Type /help for commands, colors, and ASCII emoji. /quit closes the session.")


def chat_loop(session: SecureSession) -> None:
    show_connected(session)

    def on_message(text: str) -> None:
        say("")
        say(f"<{session.peer_name}> {format_chat(safe_text(text))}")
        say("you> ")

    session.set_message_callback(on_message)
    lines: queue.Queue[str | None] = queue.Queue()

    def read_lines() -> None:
        while True:
            try:
                lines.put(input("you> "))
            except EOFError:
                lines.put(None)
                return

    threading.Thread(target=read_lines, name="chat-input", daemon=True).start()
    wiped = False
    while not session.is_closed:
        try:
            line = lines.get(timeout=0.2)
        except queue.Empty:
            continue
        if line is None:
            break
        command = line.strip().lower()
        if command in {"/quit", "/exit"}:
            break
        if not command:
            continue
        if command == "/help":
            say("/sas   show the authentication code again")
            say("/diag  show connection diagnostics")
            say("/clear clear the screen and scrollback")
            say("/wipe  clear the screen and close the session")
            say("/quit  close the direct session")
            say("Format: <c=blue>text<c>  <b>bold</b>  <i>italic</i>  <u>underline</u>")
            say("Colors: red green yellow blue magenta cyan white gray orange purple pink")
            say("Emoji: :smile: :sad: :wink: :laugh: :cry: :cool: :heart: :thumbsup:")
            continue
        if command in {"/clear", "/cls"}:
            clear_screen()
            continue
        if command in {"/wipe"}:
            clear_screen()
            wiped = True
            break
        if command == "/sas":
            say(f"SAS with {session.peer_name}: {session.sas}")
            continue
        if command == "/diag":
            for detail in session.diagnostics():
                say(detail)
            continue
        try:
            session.send(line)
        except DirectConnectError as exc:
            say(f"Send failed: {exc}")
            break
    if session.is_closed and not wiped:
        say(f"Session closed: {session.close_reason or 'peer disconnected'}")
    session.close()


def run_host(args: argparse.Namespace, *, quick: bool = True) -> None:
    name = args.name or ask(f"Your display name [{default_name()}]: ").strip() or default_name()
    if quick:
        requested = getattr(args, "code", "").strip()
        if requested:
            try:
                code = normalize_quick_code(requested)
            except InviteError as exc:
                say(f"Invalid join code: {exc}")
                return
        else:
            code = choose_quick_code(new_quick_code())
    else:
        code = ""
    port = args.port if args.port else (DEFAULT_DIRECT_PORT if quick else 0)
    config = build_config(args, name, quick_code=code, port=port)
    console = Console()
    if quick:
        callbacks = Callbacks(
            approve_incoming=lambda info: True,
            approve_sas=console.add_peer,
            log=say if (args.verbose or args.debug) else (lambda message: None),
        )
    else:
        callbacks = Callbacks(
            approve_incoming=console.incoming,
            approve_sas=console.sas,
            log=say if (args.verbose or args.debug) else (lambda message: None),
        )
    host = HostSession(config, callbacks)
    try:
        invite = host.start()
        if quick:
            show_host_endpoints(host)
            say("Waiting for a friend to join (Ctrl+C to stop)...")
            say("When someone joins, you will be asked once to add them.")
        else:
            say("")
            say("Share this invite code with your peer over a channel you trust.")
            say("It contains endpoints and a session token. It never contains chat messages.")
            say("")
            say(invite.formatted())
            say("")
            say(f"Host key: {peer_fingerprint(invite.static_public)}")
            say(f"Expires: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(invite.expires_at))}")
            say("")
            say("Waiting for an incoming request (Ctrl+C to cancel)...")
        request = host.wait_for_request(timeout=max(300.0, args.timeout * 10.0))
        session = request.accept()
        chat_loop(session)
    except KeyboardInterrupt:
        say("")
        say("Cancelled.")
    except (DirectConnectError, InviteError, OSError) as exc:
        print_error(exc)
    finally:
        host.close()


def run_join(args: argparse.Namespace) -> None:
    name = args.name or ask(f"Your display name [{default_name()}]: ").strip() or default_name()
    target = getattr(args, "invite", "")
    direct = False
    if not target:
        say("Enter the host's IP address (and port if shown), or paste a DTK1- invite.")
        target = ask("Address or invite: ").strip()
    try:
        if target.startswith(("DTK1-", "ducktalk://")):
            invite = Invite.decode(target)
            say("")
            say(f"Invite from: {invite.name}")
            say(f"Host key: {peer_fingerprint(invite.static_public)}")
            say(f"Candidates: {len(invite.candidates)}")
            say(f"Expires: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(invite.expires_at))}")
            say("The host key is carried by the invite code; verify it separately if you need")
            say("protection against someone replacing the whole code.")
        else:
            address, port = parse_endpoint(target, DEFAULT_DIRECT_PORT)
            code = getattr(args, "code", "").strip()
            if not code:
                code = ask("Join code: ").strip()
            invite = Invite.direct_for(
                address,
                port,
                code,
                include_udp=not args.no_udp,
                include_tcp=not args.no_tcp,
            )
            direct = True
            say("")
            say(f"Direct target: {format_endpoint(address, port)}")
            say(f"Join code: {format_quick_code(code)}")
            say("The join code is a shared secret; use the same code shown by the host.")
            say("Waiting for the host to add you...")
    except InviteError as exc:
        say(f"Invalid invite or address: {exc}")
        return
    config = build_config(args, name)
    console = Console()
    if direct:
        callbacks = Callbacks(
            approve_incoming=lambda info: True,
            approve_sas=console.accept_sas,
            log=say if (args.verbose or args.debug) else (lambda message: None),
        )
    else:
        callbacks = Callbacks(
            approve_incoming=console.incoming,
            approve_sas=console.sas,
            log=say if (args.verbose or args.debug) else (lambda message: None),
        )
    joiner = JoinSession(config, callbacks, invite)
    try:
        session = joiner.connect()
        chat_loop(session)
    except KeyboardInterrupt:
        say("")
        say("Cancelled.")
    except (DirectConnectError, InviteError, OSError) as exc:
        print_error(exc)
    finally:
        joiner.close()


def run_diagnostics(args: argparse.Namespace) -> None:
    name = args.name or default_name()
    config = build_config(args, name)
    rows: list[tuple[int, str | None, int | None, list]] = []
    say("DuckTalk network diagnostics")
    say("No relay, TURN service, or port prediction is used.")
    say("")
    if not config.enable_udp:
        say("UDP is disabled; no STUN or UDP candidate diagnostics are possible.")
        return
    for family in config.families:
        key = f"udp{family}"
        bind_ip = "0.0.0.0" if family == 4 else "::"
        try:
            endpoint = UdpEndpoint(family, bind_ip, key)
        except OSError as exc:
            say(f"IPv{family} UDP unavailable: {exc}")
            continue
        try:
            addresses = gather_host_addresses(family, config.allow_loopback)
            say(f"IPv{family} local addresses: {', '.join(addresses) if addresses else 'none'}")
            observations = []
            for server in config.stun_servers:
                observation = stun_discover_on_socket(
                    endpoint.sock, server, family=family, timeout=config.stun_timeout
                )
                observations.append(observation)
            local_ip = addresses[0] if addresses else None
            rows.append((family, local_ip, endpoint.local_port, observations))
        finally:
            endpoint.close()
    profile = NatProfile.from_sockets(rows, config.stun_servers)
    for line in profile.as_lines():
        say(line)
    say("")
    say("TCP reachability cannot be tested without a peer. A successful STUN mapping")
    say("does not prove that a direct path exists; hole punching still has to succeed.")


def show_about() -> None:
    say("")
    say(f"DuckTalk {__version__}")
    say("Direct peer-to-peer chat. No relay servers, no central message transport,")
    say("no hidden proxying, and no chat history stored by the application.")
    say("")
    say("Security:")
    say("  - Noise XX (X25519, ChaCha20-Poly1305, SHA-256) authenticates both peers.")
    say("  - An 8-digit SAS must match on both screens before chat is enabled.")
    say("  - Direct mode derives the control token from a short join code.")
    say("  - Join codes and full invites carry endpoints and a session secret, never chat.")
    say("")
    say("Limits:")
    say("  - Symmetric NAT, CGNAT, and restrictive firewalls can prevent a direct path.")
    say("  - There is no relay fallback. If no direct path works, the session fails.")
    say("  - Join codes and invite codes are bearer secrets; share them privately.")
    say("  - Signalling is manual by design; strangers need a way to exchange addresses.")


def show_menu(args: argparse.Namespace) -> None:
    say("")
    say(f"DuckTalk {__version__} - direct, encrypted, no relay, no history")
    local_ips: list[str] = []
    for family in (4, 6):
        for address in gather_host_addresses(family, args.allow_loopback):
            if address not in local_ips:
                local_ips.append(address)
    if local_ips:
        say(f"Your local IP: {', '.join(local_ips)}")
    else:
        say("Your local IP: unavailable")
    while True:
        say("")
        say("1. Host direct (starts the direct server; shows IP + code)")
        say("2. Join with IP + code or an invite")
        say("3. Network diagnostics")
        say("4. About and limitations")
        say("0. Exit")
        say("Press Enter to start hosting. No relay is used.")
        choice = ask("Select [1]: ").strip().lower()
        if STDIN_CLOSED:
            return
        if not choice:
            choice = "1"
        if choice in {"1", "host"}:
            run_host(args, quick=True)
        elif choice in {"2", "join"}:
            run_join(args)
        elif choice in {"3", "diagnose"}:
            run_diagnostics(args)
        elif choice in {"4", "about"}:
            show_about()
        elif choice in {"0", "q", "quit", "exit"}:
            return
        else:
            say("Unknown choice.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ducktalk",
        description="Direct peer-to-peer encrypted chat with no relay and no history.",
    )
    parser.add_argument("--version", action="version", version=f"DuckTalk {__version__}")
    parser.add_argument("-m", "--menu", action="store_true", help="open the interactive menu")
    parser.add_argument("--name", default="", help="display name shown to the peer")
    parser.add_argument(
        "--stun",
        action="append",
        default=None,
        help="STUN server host:port; repeat for more; use 'none' to disable",
    )
    parser.add_argument("--no-udp", action="store_true", help="disable UDP candidates")
    parser.add_argument("--no-tcp", action="store_true", help="disable direct TCP candidates")
    parser.add_argument(
        "--families",
        choices=("both", "ipv4", "ipv6"),
        default="both",
        help="address families to use",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="connect timeout in seconds")
    parser.add_argument("--stun-timeout", type=float, default=1.2, help="per-STUN timeout")
    parser.add_argument("--allow-loopback", action="store_true", help="include loopback candidates")
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help=f"fixed UDP/TCP port when hosting (default: {DEFAULT_DIRECT_PORT} for direct, 0 for invite)",
    )
    parser.add_argument("--debug", action="store_true", help="print internal path events")
    parser.add_argument("--verbose", action="store_true", help="print NAT and path details")
    sub = parser.add_subparsers(dest="command")
    host_parser = sub.add_parser("host", help="host a direct session and show your IP + code")
    host_parser.add_argument(
        "--invite",
        action="store_true",
        help="use a full DTK1- invite instead of the direct IP + code flow",
    )
    host_parser.add_argument(
        "--code",
        default="",
        help="10-character direct join code chosen by the host (prompted if omitted)",
    )
    join_parser = sub.add_parser("join", help="join using an IP + code or an invite")
    join_parser.add_argument("invite", nargs="?", default="", help="IP address, IP:port, or invite code")
    join_parser.add_argument("--code", default="", help="10-character direct join code")
    sub.add_parser("diagnose", help="run network and NAT diagnostics")
    sub.add_parser("about", help="show limitations and security notes")
    return parser


def main(argv: list[str] | None = None) -> int:
    enable_ansi()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.no_udp and args.no_tcp:
        parser.error("at least one of UDP or TCP must be enabled")
    try:
        if args.menu or not args.command:
            show_menu(args)
        elif args.command == "host":
            run_host(args, quick=not args.invite)
        elif args.command == "join":
            run_join(args)
        elif args.command == "diagnose":
            run_diagnostics(args)
        elif args.command == "about":
            show_about()
    except KeyboardInterrupt:
        say("")
        say("Interrupted.")
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
