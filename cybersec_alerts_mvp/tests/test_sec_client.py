"""Tests for SEC feed and filing-index parsing."""

from cybersec_alerts.sec_client import SecClient


ATOM = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>8-K - Example Corp (0000123456) (Filer)</title>
    <updated>2026-09-07T12:00:00-04:00</updated>
    <link href="https://www.sec.gov/Archives/edgar/data/123456/
000012345626000001/0000123456-26-000001-index.htm" />
  </entry>
</feed>
""".replace("\n000012345626", "000012345626")


INDEX_HTML = """
<html><body>
<a href="/Archives/edgar/data/123456/000012345626000001/example-8k.htm">
example-8k.htm</a>
<a href="/Archives/edgar/data/123456/000012345626000001/ex991.htm">
ex991.htm</a>
</body></html>
"""


def test_atom_parsing_normalizes_company_and_accession() -> None:
    entry = SecClient._parse_atom(ATOM)[0]
    assert entry.company_name == "Example Corp"
    assert entry.cik == "0000123456"
    assert entry.accession == "0000123456-26-000001"


def test_primary_document_uses_first_archive_document() -> None:
    url = SecClient._primary_document_url(INDEX_HTML)
    assert url.endswith("/example-8k.htm")
