"""SEC EDGAR ingestion client."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
import re
import time
from urllib import parse, request
from xml.etree import ElementTree

from cybersec_alerts.models import SecFiling
from cybersec_alerts.text_utils import html_to_text


CURRENT_FILINGS_URL = "https://www.sec.gov/cgi-bin/browse-edgar"
SEC_BASE_URL = "https://www.sec.gov"


class SecClientError(RuntimeError):
    """Raised when an SEC request or parse operation fails."""


@dataclass(frozen=True, slots=True)
class FeedEntry:
    """Minimal EDGAR current-filings feed entry."""

    company_name: str
    cik: str
    form: str
    filed_at: datetime
    filing_url: str
    accession: str


class _IndexLinkParser(HTMLParser):
    """Collects anchor links from an EDGAR filing index page."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href = ""
        self._text_parts: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.lower() != "a":
            return
        values = dict(attrs)
        self._href = values.get("href") or ""
        self._text_parts = []

    def handle_data(self, data: str) -> None:
        if self._href:
            self._text_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href:
            label = " ".join(self._text_parts).strip()
            self.links.append((self._href, label))
            self._href = ""
            self._text_parts = []


class SecClient:
    """Fetches current 8-K filings from SEC EDGAR."""

    def __init__(
        self,
        user_agent: str,
        timeout_seconds: float = 20.0,
        min_request_interval: float = 0.12,
    ) -> None:
        """Initializes the client.

        Args:
            user_agent: Descriptive SEC User-Agent with contact information.
            timeout_seconds: Network timeout per request.
            min_request_interval: Minimum delay between SEC requests.
        """
        if not user_agent:
            raise ValueError(
                "SEC_USER_AGENT is required for live SEC requests."
            )
        self._user_agent = user_agent
        self._timeout_seconds = timeout_seconds
        self._min_request_interval = min_request_interval
        self._last_request_at = 0.0

    def list_current_8k(self, limit: int = 40) -> list[FeedEntry]:
        """Returns current Form 8-K feed entries.

        Args:
            limit: Maximum feed entries requested from EDGAR.

        Returns:
            Parsed current-filings entries.
        """
        count = max(1, min(limit, 100))
        query = parse.urlencode(
            {
                "action": "getcurrent",
                "type": "8-K",
                "company": "",
                "dateb": "",
                "owner": "include",
                "start": 0,
                "count": count,
                "output": "atom",
            }
        )
        payload = self._get(f"{CURRENT_FILINGS_URL}?{query}")
        return self._parse_atom(payload)[:limit]

    def fetch_filing(self, entry: FeedEntry) -> SecFiling:
        """Downloads and normalizes a filing from a feed entry.

        Args:
            entry: Current-filings feed entry.

        Returns:
            Fully normalized SEC filing.
        """
        index_html = self._get(entry.filing_url)
        document_url = self._primary_document_url(index_html)
        document_html = self._get(document_url)
        text = html_to_text(document_html)
        items = tuple(
            sorted(
                set(
                    re.findall(
                        r"\bItem\s+(1\.05|8\.01)\b",
                        text,
                        flags=re.IGNORECASE,
                    )
                )
            )
        )
        return SecFiling(
            cik=entry.cik,
            company_name=entry.company_name,
            form=entry.form,
            accession=entry.accession,
            filed_at=entry.filed_at,
            filing_url=entry.filing_url,
            document_url=document_url,
            text=text,
            items=items,
        )

    def _get(self, url: str) -> str:
        now = time.monotonic()
        delay = self._min_request_interval - (now - self._last_request_at)
        if delay > 0:
            time.sleep(delay)

        req = request.Request(
            url,
            headers={
                "User-Agent": self._user_agent,
                "Accept": "text/html,application/atom+xml,*/*;q=0.8",
            },
        )
        try:
            with request.urlopen(
                req,
                timeout=self._timeout_seconds,
            ) as response:
                raw = response.read()
                charset = response.headers.get_content_charset() or "utf-8"
        except OSError as exc:
            raise SecClientError(f"SEC request failed: {url}") from exc
        finally:
            self._last_request_at = time.monotonic()
        return raw.decode(charset, errors="replace")

    @staticmethod
    def _parse_atom(payload: str) -> list[FeedEntry]:
        namespace = {"atom": "http://www.w3.org/2005/Atom"}
        root = ElementTree.fromstring(payload)
        entries: list[FeedEntry] = []
        for node in root.findall("atom:entry", namespace):
            title = node.findtext(
                "atom:title", default="", namespaces=namespace
            )
            updated = node.findtext(
                "atom:updated",
                default="",
                namespaces=namespace,
            )
            link = node.find("atom:link", namespace)
            href = link.attrib.get("href", "") if link is not None else ""
            company_name, form, cik = _parse_feed_title(title)
            accession = _accession_from_url(href)
            entries.append(
                FeedEntry(
                    company_name=company_name,
                    cik=cik,
                    form=form,
                    filed_at=_parse_datetime(updated),
                    filing_url=href,
                    accession=accession,
                )
            )
        return entries

    @staticmethod
    def _primary_document_url(index_html: str) -> str:
        parser = _IndexLinkParser()
        parser.feed(index_html)
        candidates: list[str] = []
        for href, label in parser.links:
            lower = href.lower()
            if not lower.endswith((".htm", ".html")):
                continue
            if "-index" in lower:
                continue
            if label.strip().lower() in {"8-k", "8-k/a"}:
                return parse.urljoin(SEC_BASE_URL, href)
            if "/archives/edgar/data/" in lower:
                candidates.append(href)
        if not candidates:
            raise SecClientError("Could not identify primary filing document.")
        return parse.urljoin(SEC_BASE_URL, candidates[0])


def _parse_feed_title(title: str) -> tuple[str, str, str]:
    """Parses common EDGAR current-feed title formats."""
    cleaned = re.sub(r"\s+", " ", title).strip()
    form_match = re.search(r"\b(8-K(?:/A)?)\b", cleaned, re.IGNORECASE)
    cik_match = re.search(r"\((\d{7,10})\)", cleaned)
    form = form_match.group(1).upper() if form_match else "8-K"
    cik = cik_match.group(1).zfill(10) if cik_match else ""

    company = cleaned
    if form_match:
        company = cleaned[form_match.end() :].lstrip(" -:")
    if cik_match:
        company = company.replace(cik_match.group(0), "").strip(" -")
    company = re.sub(r"\s*\((Filer|Issuer)\)\s*$", "", company)
    return company or "Unknown registrant", form, cik


def _accession_from_url(url: str) -> str:
    match = re.search(r"(\d{10}-\d{2}-\d{6})", url)
    if match:
        return match.group(1)
    compact = re.search(r"/(\d{18})/", url)
    if not compact:
        return url
    raw = compact.group(1)
    return f"{raw[:10]}-{raw[10:12]}-{raw[12:]}"


def _parse_datetime(value: str) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return datetime.now(timezone.utc)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
