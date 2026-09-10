"""Command line interface."""

from __future__ import annotations

import argparse
import logging
import sys

from cybersec_alerts.config import Settings
from cybersec_alerts.demo import build_demo_alerts
from cybersec_alerts.enforcement import SecEnforcementClient
from cybersec_alerts.pipeline import AlertPipeline, render_alerts
from cybersec_alerts.sec_client import SecClient
from cybersec_alerts.store import Store


def main(argv: list[str] | None = None) -> int:
    """Runs the command-line application.

    Args:
        argv: Optional argument vector for testing.

    Returns:
        Process-style return code.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.command == "demo":
        print(render_alerts(build_demo_alerts()))
        return 0

    settings = Settings.from_env()
    store = Store(settings.db_path)

    if args.command == "history":
        for row in store.recent_alerts(limit=args.limit):
            print(
                f"{row['created_at']} | {row['alert_type']} | "
                f"{row['company_name']} | {row['accession']}"
            )
        return 0

    if args.command == "scan":
        if not settings.sec_user_agent:
            parser.error(
                "SEC_USER_AGENT is required for live scans. Example: "
                "CyberSecAlerts/0.1 analyst@example.com"
            )
        sec_client = SecClient(
            user_agent=settings.sec_user_agent,
            timeout_seconds=settings.timeout_seconds,
        )
        enforcement_client = SecEnforcementClient(
            user_agent=settings.sec_user_agent,
            timeout_seconds=settings.timeout_seconds,
        )
        pipeline = AlertPipeline(
            sec_client=sec_client,
            enforcement_client=enforcement_client,
            store=store,
            minimum_alert_score=settings.minimum_alert_score,
        )
        alerts = pipeline.run_once(
            limit=args.limit,
            enforcement_pages=settings.enforcement_pages,
        )
        if alerts:
            print("\n\n".join(alerts))
        else:
            print("No new qualifying cyber alerts in this scan.")
        return 0

    parser.print_help()
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybersec-alerts",
        description="Actionable SEC cybersecurity filing alerts.",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser(
        "demo",
        help="Run an offline synthetic Item 1.05/8.01 demonstration.",
    )

    scan = subparsers.add_parser(
        "scan",
        help="Scan current SEC Form 8-K filings.",
    )
    scan.add_argument(
        "--limit",
        type=int,
        default=40,
        help="Maximum current 8-K feed entries to inspect.",
    )

    history = subparsers.add_parser(
        "history",
        help="Show persisted alert history.",
    )
    history.add_argument("--limit", type=int, default=20)
    return parser


if __name__ == "__main__":
    sys.exit(main())
