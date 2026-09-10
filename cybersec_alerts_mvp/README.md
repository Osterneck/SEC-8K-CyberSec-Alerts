# CyberSec Alerts MVP

A purpose-built U.S. securities/legal compliance alerting service for SEC
cybersecurity disclosures. The MVP ingests recent Form 8-K filings, separates
Item 1.05 material cybersecurity incidents from cyber-related Item 8.01
voluntary/other disclosures, scores downstream exposure, correlates recent SEC
civil litigation and administrative enforcement releases, persists state, and renders plain-English alerts.

## Target users

- Cyber insurance underwriters and carriers
- Securities, privacy, and cybersecurity law firms
- Institutional investors and hedge funds
- Corporate GC/CCO offices
- Big Four and mid-market accounting/advisory firms
- Third-party risk and vendor-management teams

## Core workflow

```text
SEC filing
  -> Item detection
  -> cyber classification
  -> materiality state
  -> exposure scoring
  -> SEC enforcement correlation
  -> plain-English actionable alert
  -> SQLite history/deduplication
```

## Regulatory distinction implemented

- **Item 1.05:** material cybersecurity incident disclosed after the registrant
  determines the incident is material.
- **Cyber-related Item 8.01:** voluntary/other cybersecurity disclosure,
  including an incident not yet determined material or determined immaterial.

The classifier does not treat all Item 8.01 filings as cyber events.

## Quick start

The project has no runtime third-party dependencies.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -e .

export SEC_USER_AGENT="CyberSecAlerts/0.1 your-email@example.com"
cybersec-alerts demo
cybersec-alerts scan --limit 25
```

The SEC requests that automated clients identify themselves with a descriptive
User-Agent. Set `SEC_USER_AGENT` to a real product/contact value before live
use.

## Useful commands

```bash
cybersec-alerts demo
cybersec-alerts scan --limit 50
cybersec-alerts history --limit 20
pytest -q
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SEC_USER_AGENT` | none | Required for live SEC requests |
| `CYBERSEC_DB_PATH` | `cybersec_alerts.db` | SQLite database |
| `CYBERSEC_TIMEOUT_SECONDS` | `20` | HTTP timeout |
| `CYBERSEC_ENFORCEMENT_PAGES` | `3` | Litigation-release pages |
| `CYBERSEC_MIN_SCORE` | `20` | Minimum risk score for alert |


## Official SEC references used for the MVP

- Cybersecurity final rule:
  `https://www.sec.gov/rules-regulations/2023/07/s7-09-22`
- SEC CorpFin Item 1.05 / Item 8.01 clarification:
  `https://www.sec.gov/newsroom/whats-new/gerding-cybersecurity-incidents-05212024`
- EDGAR APIs:
  `https://www.sec.gov/search-filings/edgar-application-programming-interfaces`
- SEC Litigation Releases:
  `https://www.sec.gov/enforcement-litigation/litigation-releases`
- SEC Administrative Proceedings:
  `https://www.sec.gov/enforcement-litigation/administrative-proceedings`

## Architecture

- `sec_client.py` - EDGAR current-filings ingestion and filing retrieval
- `classifier.py` - Item 1.05 / cyber-8.01 detection and fact extraction
- `scoring.py` - exposure, urgency, and audience-action scoring
- `enforcement.py` - SEC litigation-release ingestion/correlation
- `store.py` - SQLite state, deduplication, and alert history
- `alerts.py` - deterministic plain-English alert rendering
- `pipeline.py` - orchestration
- `cli.py` - command line entry point

## MVP limitations

This is deliberately a rough-draft production architecture, not a finished
commercial platform. Current limitations include:

1. Enforcement correlation is entity-name based and should later add CIK,
   LEI, ticker, former-name, subsidiary, and fuzzy entity resolution.
2. The MVP monitors SEC civil litigation releases and administrative
   proceedings. A later iteration should add enforcement press releases,
   richer order text, and relevant federal/private litigation sources.
3. Materiality scoring is deterministic and explainable. A later iteration can
   add a validated legal-NLP layer while retaining the deterministic rules as
   guardrails.
4. Alert delivery adapters (email, Slack, Teams, webhook) are not yet included.
5. Cross-filing incident threading should later link Item 8.01 -> Item 1.05 ->
   8-K/A -> 10-Q/10-K -> enforcement/litigation.

## Important

This software produces legal/risk intelligence signals, not legal advice,
coverage determinations, or investment recommendations. Human review remains
necessary for materiality, causation, insurance coverage, liability, and
trading decisions.
