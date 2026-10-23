from ducktalk.formatting import format_chat


def test_color_tag() -> None:
    assert format_chat("<c=blue>hi<c>", color=True) == "\x1b[34mhi\x1b[0m"


def test_unclosed_color_is_reset() -> None:
    assert format_chat("<c=red>hi", color=True) == "\x1b[31mhi\x1b[0m"


def test_nested_color_restores_previous_color() -> None:
    assert (
        format_chat("<c=red>a<c=blue>b<c>c</c>", color=True)
        == "\x1b[31ma\x1b[34mb\x1b[0m\x1b[31mc\x1b[0m"
    )


def test_styles() -> None:
    assert (
        format_chat("<b>bold</b> <i>italic</i> <u>under</u>", color=True)
        == "\x1b[1mbold\x1b[0m \x1b[3mitalic\x1b[0m \x1b[4munder\x1b[0m"
    )


def test_hex_color() -> None:
    assert (
        format_chat("<c=#ff0000>red<c>", color=True)
        == "\x1b[38;2;255;0;0mred\x1b[0m"
    )


def test_ascii_emoji() -> None:
    assert format_chat(":smile: :heart: :duck:", color=False) == ":) <3 (o)>"


def test_tags_are_removed_without_color() -> None:
    assert format_chat("<c=blue>hi<c> <b>bold</b>", color=False) == "hi bold"


def test_unknown_color_is_literal() -> None:
    assert format_chat("<c=nope>hi<c>", color=True) == "<c=nope>hi<c>"


def test_raw_control_characters_are_escaped() -> None:
    output = format_chat("\x1b[31mred", color=False)
    assert "\x1b" not in output
    assert output == "\\x1b[31mred"
