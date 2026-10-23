"""Chat text formatting: ANSI colors, styles, and ASCII emoticons."""

from __future__ import annotations

import os
import re
import sys

RESET = "\x1b[0m"

COLOR_CODES = {
    "black": "30",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "white": "37",
    "default": "39",
    "gray": "90",
    "grey": "90",
    "brightblack": "90",
    "brightred": "91",
    "brightgreen": "92",
    "brightyellow": "93",
    "brightblue": "94",
    "brightmagenta": "95",
    "brightcyan": "96",
    "brightwhite": "97",
    "lightred": "91",
    "lightgreen": "92",
    "lightyellow": "93",
    "lightblue": "94",
    "lightmagenta": "95",
    "lightcyan": "96",
    "orange": "38;5;208",
    "purple": "38;5;129",
    "pink": "38;5;213",
    "lime": "38;5;118",
    "teal": "38;5;37",
    "gold": "38;5;220",
}

STYLE_ALIASES = {
    "b": "bold",
    "bold": "bold",
    "i": "italic",
    "italic": "italic",
    "u": "underline",
    "underline": "underline",
    "dim": "dim",
    "rev": "reverse",
    "reverse": "reverse",
}

STYLE_CODES = {
    "bold": "1",
    "italic": "3",
    "underline": "4",
    "dim": "2",
    "reverse": "7",
}

EMOJI = {
    "smile": ":)",
    "sad": ":(",
    "wink": ";)",
    "laugh": ":D",
    "cry": ":'(",
    "cool": "B)",
    "heart": "<3",
    "star": "*",
    "fire": "[fire]",
    "thumbsup": "(y)",
    "thumbsdown": "(n)",
    "shrug": "\\_(o_o)_/",
    "wave": "o/",
    "party": "\\o/",
    "check": "[ok]",
    "x": "[x]",
    "duck": "(o)>",
    "rocket": ">>",
}

TAG_RE = re.compile(r"<(/?)([a-zA-Z]+)(?:=([^<>]*))?>")
EMOJI_RE = re.compile(r":([a-zA-Z0-9_+-]+):")

_ansi_enabled = False


def enable_ansi() -> bool:
    """Enable ANSI processing for the current console, if possible."""
    global _ansi_enabled
    if "NO_COLOR" in os.environ:
        _ansi_enabled = False
        return False
    try:
        if not sys.stdout.isatty():
            _ansi_enabled = False
            return False
    except Exception:
        _ansi_enabled = False
        return False
    if os.name != "nt":
        _ansi_enabled = True
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            _ansi_enabled = False
            return False
        virtual_terminal = 0x0004
        if mode.value & virtual_terminal:
            _ansi_enabled = True
            return True
        if not kernel32.SetConsoleMode(handle, mode.value | virtual_terminal):
            _ansi_enabled = False
            return False
        _ansi_enabled = True
        return True
    except Exception:
        _ansi_enabled = False
        return False


def ansi_enabled() -> bool:
    return _ansi_enabled


def clear_screen() -> None:
    """Clear the visible screen and scrollback when the terminal supports it."""
    try:
        if not sys.stdout.isatty():
            return
    except Exception:
        return
    if _ansi_enabled:
        try:
            sys.stdout.write(RESET + "\x1b[2J\x1b[3J\x1b[H")
            sys.stdout.flush()
            return
        except Exception:
            pass
    os.system("cls" if os.name == "nt" else "clear")


def _clean(text: str) -> str:
    return "".join(
        ch if ch.isprintable() or ch in "\n\t" else f"\\x{ord(ch):02x}" for ch in text
    )


def _color_code(value: str) -> str | None:
    name = value.strip().lower()
    if name.startswith("#"):
        digits = name[1:]
        if len(digits) == 3:
            digits = "".join(ch * 2 for ch in digits)
        if len(digits) != 6 or any(ch not in "0123456789abcdef" for ch in digits):
            return None
        red = int(digits[0:2], 16)
        green = int(digits[2:4], 16)
        blue = int(digits[4:6], 16)
        return f"38;2;{red};{green};{blue}"
    return COLOR_CODES.get(name)


def _emoji(text: str) -> str:
    return EMOJI_RE.sub(
        lambda match: EMOJI.get(match.group(1).lower(), match.group(0)),
        text,
    )


def _last_index(active: list[tuple[str, str]], kind: str) -> int | None:
    for index in range(len(active) - 1, -1, -1):
        if active[index][0] == kind:
            return index
    return None


def _reapply(active: list[tuple[str, str]]) -> str:
    return RESET + "".join(f"\x1b[{code}m" for _, code in active)


def format_chat(text: str, *, color: bool | None = None) -> str:
    """Render chat markup to ANSI text, or plain text when color is disabled."""
    use_color = _ansi_enabled if color is None else color
    text = _clean(text)
    active: list[tuple[str, str]] = []
    parts: list[str] = []
    cursor = 0

    for match in TAG_RE.finditer(text):
        parts.append(_emoji(text[cursor : match.start()]))
        cursor = match.end()
        closing = bool(match.group(1))
        name = match.group(2).lower()
        value = match.group(3)

        if name in {"c", "color"}:
            if closing or value is None or not value.strip():
                index = _last_index(active, "color")
                if index is None:
                    parts.append(match.group(0))
                else:
                    active.pop(index)
                    if use_color:
                        parts.append(_reapply(active))
                continue
            code = _color_code(value)
            if code is None:
                parts.append(match.group(0))
                continue
            if use_color:
                parts.append(f"\x1b[{code}m")
            active.append(("color", code))
            continue

        style = STYLE_ALIASES.get(name)
        if style is None or value is not None:
            parts.append(match.group(0))
            continue
        if closing:
            index = _last_index(active, style)
            if index is None:
                parts.append(match.group(0))
            else:
                active.pop(index)
                if use_color:
                    parts.append(_reapply(active))
        else:
            code = STYLE_CODES[style]
            if use_color:
                parts.append(f"\x1b[{code}m")
            active.append((style, code))

    parts.append(_emoji(text[cursor:]))
    if use_color and active:
        parts.append(RESET)
    return "".join(parts)
