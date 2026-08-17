"""Command line entry point: ``python -m agp <command>``.

Every command exits non-zero when an active finding reaches ``--fail-on``, so
the same code that produces the auditor's report also gates a pipeline.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .access_review import AccessReviewBuilder
from .iam_analyzer import IamAnalyzer, load_policies, to_entitlements
from .models import Severity, load_roster
from .policy import GovernancePolicy
from .privacy import PrivacyAnalyzer, build_ropa, load_inventory
from .report import (
    campaign_to_markdown,
    ropa_to_markdown,
    summarize,
    to_json,
    to_markdown,
    worst_severity,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agp",
        description="Access governance and privacy engineering checks for Google Cloud.",
    )
    parser.add_argument("--version", action="version", version=f"agp {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "--config",
            type=Path,
            help="Governance policy YAML (defaults to built-in baseline).",
        )
        sub.add_argument(
            "--format",
            choices=("md", "json"),
            default="md",
            help="Output format (default: md).",
        )
        sub.add_argument("--out", type=Path, help="Write output here instead of stdout.")
        sub.add_argument(
            "--fail-on",
            default="high",
            help="Exit non-zero when a finding reaches this severity, or 'none'.",
        )

    iam = subparsers.add_parser(
        "iam-scan", help="Find least-privilege violations in an IAM allow policy."
    )
    iam.add_argument("--policy", type=Path, required=True, help="IAM policy JSON.")
    common(iam)

    review = subparsers.add_parser(
        "access-review", help="Generate a user access review campaign."
    )
    review.add_argument("--policy", type=Path, required=True, help="IAM policy JSON.")
    review.add_argument("--roster", type=Path, help="HR roster CSV.")
    review.add_argument("--name", default="", help="Campaign name.")
    review.add_argument(
        "--csv", type=Path, help="Also write the reviewer worklist to this CSV."
    )
    common(review)

    privacy = subparsers.add_parser(
        "privacy-scan", help="Check the data inventory against privacy requirements."
    )
    privacy.add_argument(
        "--inventory", type=Path, required=True, help="Data inventory YAML."
    )
    common(privacy)

    ropa = subparsers.add_parser(
        "ropa", help="Render the record of processing activities from the inventory."
    )
    ropa.add_argument(
        "--inventory", type=Path, required=True, help="Data inventory YAML."
    )
    ropa.add_argument("--out", type=Path, help="Write output here instead of stdout.")

    return parser


def main(argv: "list[str] | None" = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "ropa":
        rendered = ropa_to_markdown(build_ropa(load_inventory(args.inventory)))
        _emit(rendered, args.out)
        return 0

    policy = GovernancePolicy.load(args.config)

    if args.command == "iam-scan":
        bindings = load_policies(args.policy)
        findings = IamAnalyzer(policy).analyze(bindings)
        rendered = _render(
            args,
            findings,
            scan_type="iam-scan",
            title="IAM Least-Privilege Findings",
            context={
                "Organization": policy.organization,
                "Bindings analysed": str(len(bindings)),
                "Entitlements analysed": str(len(to_entitlements(bindings))),
            },
        )
    elif args.command == "access-review":
        bindings = load_policies(args.policy)
        roster = load_roster(args.roster) if args.roster else {}
        campaign = AccessReviewBuilder(policy, roster).build(
            to_entitlements(bindings), name=args.name
        )
        findings = campaign.findings
        if args.csv:
            campaign.write_csv(args.csv)
            print(f"Wrote reviewer worklist to {args.csv}", file=sys.stderr)
        if args.format == "json":
            rendered = to_json(
                findings,
                scan_type="access-review",
                extra={
                    "campaign": campaign.name,
                    "due_date": campaign.due_date,
                    "items": [item.to_row() for item in campaign.items],
                    "coverage": round(campaign.coverage, 4),
                },
            )
        else:
            rendered = campaign_to_markdown(campaign)
        _emit(rendered, args.out)
        return _exit_code(findings, args.fail_on)
    elif args.command == "privacy-scan":
        assets = load_inventory(args.inventory)
        findings = PrivacyAnalyzer(policy).analyze(assets)
        rendered = _render(
            args,
            findings,
            scan_type="privacy-scan",
            title="Privacy Engineering Findings",
            context={
                "Assets in inventory": str(len(assets)),
                "Assets holding personal data": str(
                    sum(1 for a in assets if a.holds_personal_data)
                ),
            },
        )
    else:  # pragma: no cover - argparse rejects anything else
        raise SystemExit(f"unknown command: {args.command}")

    _emit(rendered, args.out)
    return _exit_code(findings, args.fail_on)


def _render(args, findings, *, scan_type: str, title: str, context: dict) -> str:
    if args.format == "json":
        return to_json(findings, scan_type=scan_type, extra={"context": context})
    return to_markdown(findings, title=title, context=context)


def _emit(rendered: str, out: "Path | None") -> None:
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8")
        print(f"Wrote {out}", file=sys.stderr)
    else:
        print(rendered)


def _exit_code(findings, fail_on: str) -> int:
    if str(fail_on).strip().lower() in ("none", "off", ""):
        return 0
    threshold = Severity.parse(fail_on)
    worst = worst_severity(findings)
    if worst >= threshold:
        counts = summarize(findings)
        breaching = sum(
            count
            for name, count in counts.items()
            if Severity.parse(name) >= threshold
        )
        print(
            f"FAILED: {breaching} finding(s) at or above {threshold.name}.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
