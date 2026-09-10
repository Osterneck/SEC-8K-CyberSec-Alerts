"""SEC enforcement-release ingestion and entity correlation."""

from __future__ import annotations

from html.parser import HTMLParser
import re
import time
from urllib import parse, request

from cybersec_alerts.models import EnforcementAction
from cybersec_alerts.text_utils import normalize_whitespace


LITIGATION_RELEASES_URL = (
    "https://www.sec.gov/enforcement-litigation/litigation-releases"
)
ADMIN_PROCEEDINGS_URL = (
    "https://www.sec.gov/enforcement-litigation/administrative-proceedings"
)


class EnforcementClientError(RuntimeError):
    """Raised when SEC enforcement retrieval fails."""


class _ReleaseLinkParser(HTMLParser):
    """Extracts respondent links from SEC enforcement index pages."""

    def __init__(self, source_type: str) -> None:
        super().__init__()
        self.actions: list[EnforcementAction] = []
        self._source_type = source_type
        self._href = ""
        self._parts: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.lower() != "a":
            return
        self._href = dict(attrs).get("href") or ""
        self._parts = []

    def handle_data(self, data: str) -> None:
        if self._href:
            self._parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or not self._href:
            return
        label = normalize_whitespace(" ".join(self._parts))
        if label and self._is_release_href(self._href):
            self.actions.append(
                EnforcementAction(
                    title=label,
                    url=parse.urljoin("https://www.sec.gov", self._href),
                    release_number=_release_number(self._href),
                    source_type=self._source_type,
                )
            )
        self._href = ""
        self._parts = []

    def _is_release_href(self, href: str) -> bool:
        lower = href.lower()
        if self._source_type == "litigation_release":
            return "/litigation-releases/lr-" in lower
        return "/files/litigation/admin/" in lower


class SecEnforcementClient:
    """Fetches and correlates recent SEC enforcement actions."""

    def __init__(
        self,
        user_agent: str,
        timeout_seconds: float = 20.0,
        min_request_interval: float = 0.12,
    ) -> None:
        if not user_agent:
            raise ValueError(
                "SEC_USER_AGENT is required for live SEC requests."
            )
        self._user_agent = user_agent
        self._timeout_seconds = timeout_seconds
        self._min_request_interval = min_request_interval
        self._last_request_at = 0.0

    def fetch_recent(self, pages: int = 3) -> list[EnforcementAction]:
        """Returns recent SEC civil and administrative enforcement actions.

        Args:
            pages: Number of pages to inspect for each SEC index.

        Returns:
            De-duplicated enforcement actions.
        """
        actions: list[EnforcementAction] = []
        actions.extend(
            self._fetch_index(
                LITIGATION_RELEASES_URL,
                "litigation_release",
                pages,
            )
        )
        actions.extend(
            self._fetch_index(
                ADMIN_PROCEEDINGS_URL,
                "administrative_proceeding",
                pages,
            )
        )
        deduplicated: dict[str, EnforcementAction] = {}
        for action in actions:
            deduplicated.setdefault(action.url, action)
        return list(deduplicated.values())

    def correlate(
        self,
        company_name: str,
        actions: list[EnforcementAction],
    ) -> tuple[EnforcementAction, ...]:
        """Matches a company to enforcement-release titles.

        Args:
            company_name: SEC registrant name.
            actions: Candidate enforcement actions.

        Returns:
            Entity-name matches sorted in input order.
        """
        company_tokens = _entity_tokens(company_name)
        if not company_tokens:
            return ()
        matches: list[EnforcementAction] = []
        for action in actions:
            action_tokens = _entity_tokens(action.title)
            overlap = company_tokens & action_tokens
            ratio = len(overlap) / max(1, len(company_tokens))
            if ratio >= 0.6:
                matches.append(action)
        return tuple(matches)

    def _fetch_index(
        self,
        base_url: str,
        source_type: str,
        pages: int,
    ) -> list[EnforcementAction]:
        actions: list[EnforcementAction] = []
        for page_number in range(max(1, pages)):
            url = f"{base_url}?page={page_number}"
            parser = _ReleaseLinkParser(source_type)
            parser.feed(self._get(url))
            actions.extend(parser.actions)
        return actions

    def _get(self, url: str) -> str:
        now = time.monotonic()
        delay = self._min_request_interval - (now - self._last_request_at)
        if delay > 0:
            time.sleep(delay)
        req = request.Request(
            url,
            headers={
                "User-Agent": self._user_agent,
                "Accept": "text/html,*/*;q=0.8",
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
            raise EnforcementClientError(
                f"SEC enforcement request failed: {url}"
            ) from exc
        finally:
            self._last_request_at = time.monotonic()
        return raw.decode(charset, errors="replace")


def _release_number(url: str) -> str:
    litigation = re.search(r"/lr-(\d+)", url, re.IGNORECASE)
    if litigation:
        return f"LR-{litigation.group(1)}"
    administrative = re.search(
        r"/([^/]+)\.pdf(?:\?.*)?$",
        url,
        re.IGNORECASE,
    )
    return administrative.group(1) if administrative else ""


def _entity_tokens(value: str) -> set[str]:
    stopwords = {
        "and",
        "company",
        "corp",
        "corporation",
        "inc",
        "incorporated",
        "llc",
        "ltd",
        "limited",
        "plc",
        "the",
    }
    return {
        token
        for token in re.findall(r"[a-z0-9]+", value.lower())
        if len(token) > 2 and token not in stopwords
    }
