"""Text normalization helpers."""

from __future__ import annotations

from html import unescape
from html.parser import HTMLParser
import re


class _TextExtractor(HTMLParser):
    """Extracts visible text from basic HTML."""

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        del attrs
        if tag.lower() in {"script", "style"}:
            self._ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._ignored_depth == 0:
            self.parts.append(data)


def html_to_text(value: str) -> str:
    """Converts HTML to normalized text.

    Args:
        value: Source HTML.

    Returns:
        Whitespace-normalized visible text.
    """
    parser = _TextExtractor()
    parser.feed(value)
    text = unescape(" ".join(parser.parts))
    return normalize_whitespace(text)


def normalize_whitespace(value: str) -> str:
    """Collapses repeated whitespace.

    Args:
        value: Source text.

    Returns:
        Text containing single spaces between tokens.
    """
    return re.sub(r"\s+", " ", value).strip()


def sentence_candidates(value: str) -> list[str]:
    """Splits text into simple sentence candidates.

    Args:
        value: Plain text.

    Returns:
        Non-empty sentence-like strings.
    """
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9])", value)
    return [normalize_whitespace(part) for part in parts if part.strip()]
