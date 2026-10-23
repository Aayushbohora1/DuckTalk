from __future__ import annotations

import argparse

import pytest

from ducktalk import __version__
from ducktalk.candidates import (
    DEFAULT_DIRECT_PORT,
    Invite,
    InviteError,
    format_endpoint,
    format_quick_code,
    new_quick_code,
    normalize_quick_code,
    parse_endpoint,
    quick_identity,
)
from ducktalk.cli import ask_yes, build_config, build_parser, choose_quick_code, main


def parse(argv: list[str]) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def test_version_is_set() -> None:
    assert __version__ == "1.0.0"


def test_parser_defaults_and_subcommands() -> None:
    args = parse(["host"])
    assert args.command == "host"
    assert args.code == ""
    assert args.families == "both"
    assert not args.no_udp
    assert not args.no_tcp
    assert parse(["host", "--code", "ABCDE-FGHJK"]).code == "ABCDE-FGHJK"
    assert parse(["join", "DTK1-x"]).invite == "DTK1-x"


def test_build_config_disables_stun_and_sets_families() -> None:
    args = parse(["--stun", "none", "--families", "ipv4", "host"])
    config = build_config(args, "Alice")
    assert config.name == "Alice"
    assert config.stun_servers == ()
    assert config.families == (4,)
    assert config.enable_udp and config.enable_tcp


def test_build_config_parses_multiple_stun_servers() -> None:
    args = parse(["--stun", "a:1,b:2", "--stun", "c:3", "host"])
    config = build_config(args, "Bob")
    assert config.stun_servers == ("a:1", "b:2", "c:3")


def test_choose_quick_code_accepts_host_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ducktalk.cli.ask", lambda prompt: "abcde-fghjk")
    assert choose_quick_code("ZZZZZZZZZZ") == "ABCDEFGHJK"


def test_choose_quick_code_uses_default_on_enter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ducktalk.cli.ask", lambda prompt: "")
    assert choose_quick_code("ZZZZZZZZZZ") == "ZZZZZZZZZZ"


def test_ask_yes_reprompts_on_invalid_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = iter(["h", "y"])
    monkeypatch.setattr("ducktalk.cli.ask", lambda prompt: next(answers))
    assert ask_yes("Add peer?")


def test_menu_exits(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("builtins.input", lambda prompt="": "0")
    assert main(["-m"]) == 0
    output = capsys.readouterr().out
    assert "DuckTalk" in output
    assert "Host direct" in output
    assert "Join with IP + code" in output


def test_join_with_invalid_invite(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    answers = iter(["Tester", "garbage"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert main(["--stun", "none", "join"]) == 0
    output = capsys.readouterr().out
    assert "Invalid invite" in output


def test_both_transports_disabled_is_rejected() -> None:
    with pytest.raises(SystemExit):
        main(["--no-udp", "--no-tcp", "host"])


def test_quick_code_round_trip_and_identity() -> None:
    code = new_quick_code()
    assert len(code) == 10
    assert normalize_quick_code(format_quick_code(code)) == code
    sid, token = quick_identity(code)
    assert len(sid) == len(token) == 16
    assert quick_identity(code.lower()) == (sid, token)


def test_parse_direct_endpoint() -> None:
    assert parse_endpoint("192.0.2.10") == ("192.0.2.10", DEFAULT_DIRECT_PORT)
    assert parse_endpoint("192.0.2.10:5000") == ("192.0.2.10", 5000)
    assert parse_endpoint("[2001:db8::1]:5000") == ("2001:db8::1", 5000)
    assert parse_endpoint("2001:db8::1") == ("2001:db8::1", DEFAULT_DIRECT_PORT)
    assert format_endpoint("2001:db8::1", 5000) == "[2001:db8::1]:5000"


def test_direct_invite_uses_shared_code() -> None:
    code = new_quick_code()
    invite = Invite.direct_for("192.0.2.10", 5000, code)
    sid, token = quick_identity(code)
    assert invite.direct
    assert invite.session_id == sid
    assert invite.token == token
    assert invite.name == ""
    assert {candidate.protocol for candidate in invite.candidates} == {"udp", "tcp"}
    assert all(candidate.port == 5000 for candidate in invite.candidates)


def test_host_accepts_direct_port() -> None:
    args = parse(["--port", "5000", "host"])
    config = build_config(args, "Alice", quick_code=new_quick_code(), port=5000)
    assert config.port == 5000
    assert len(config.quick_code) == 10


def test_invalid_direct_inputs_are_rejected() -> None:
    with pytest.raises(InviteError):
        parse_endpoint("0.0.0.0")
    with pytest.raises(InviteError):
        parse_endpoint("0.0.0.0:47777")
    with pytest.raises(InviteError):
        parse_endpoint("224.0.0.1")
    with pytest.raises(InviteError):
        parse_endpoint("fe80::1")
    with pytest.raises(InviteError):
        parse_endpoint("not-an-ip")
    with pytest.raises(InviteError):
        normalize_quick_code("short")
