"""Rendering of findings and campaigns into Markdown and JSON.

Markdown is what a reviewer or auditor reads; JSON is what a pipeline gates on.
Both come from the same finding objects so they can never disagree.
"""

from __future__ import annotations

import datetime as _dt
import json
from typing import Any, Iterable, Sequence

from .access_review import Campaign
from .models import Finding, Severity

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def summarize(findings: Iterable[Finding]) -> dict[str, int]:
    """Count active (non-suppressed) findings per severity."""
    counts = {severity.name: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        if finding.is_suppressed:
            continue
        counts[finding.severity.name] += 1
    return counts


def worst_severity(findings: Iterable[Finding]) -> Severity:
    active = [f.severity for f in findings if not f.is_suppressed]
    return max(active) if active else Severity.INFO


def to_json(
    findings: Sequence[Finding],
    *,
    scan_type: str,
    generated_at: "_dt.datetime | None" = None,
    extra: "dict[str, Any] | None" = None,
) -> str:
    generated_at = generated_at or _dt.datetime.now(_dt.timezone.utc)
    payload: dict[str, Any] = {
        "scan_type": scan_type,
        "generated_at": generated_at.isoformat(),
        "summary": summarize(findings),
        "suppressed": sum(1 for f in findings if f.is_suppressed),
        "findings": [f.to_dict() for f in findings],
    }
    if extra:
        payload.update(extra)
    return json.dumps(payload, indent=2)


def to_markdown(
    findings: Sequence[Finding],
    *,
    title: str,
    generated_at: "_dt.datetime | None" = None,
    context: "dict[str, str] | None" = None,
) -> str:
    generated_at = generated_at or _dt.datetime.now(_dt.timezone.utc)
    counts = summarize(findings)
    suppressed = [f for f in findings if f.is_suppressed]
    active = [f for f in findings if not f.is_suppressed]

    lines = [
        f"# {title}",
        "",
        f"_Generated {generated_at:%Y-%m-%d %H:%M UTC}_",
        "",
    ]
    if context:
        for key, value in context.items():
            lines.append(f"- **{key}:** {value}")
        lines.append("")

    lines += [
        "## Summary",
        "",
        "| Severity | Findings |",
        "| --- | ---: |",
    ]
    for severity in SEVERITY_ORDER:
        lines.append(f"| {severity.name} | {counts[severity.name]} |")
    lines.append(f"| _Suppressed by exception_ | {len(suppressed)} |")
    lines.append("")

    if not active:
        lines += ["No active findings. ", ""]

    for severity in SEVERITY_ORDER:
        bucket = [f for f in active if f.severity == severity]
        if not bucket:
            continue
        lines += [f"## {severity.name} ({len(bucket)})", ""]
        for finding in bucket:
            lines += _render_finding(finding)

    if suppressed:
        lines += ["## Suppressed by accepted exception", ""]
        for finding in suppressed:
            lines.append(
                f"- `{finding.rule_id}` {finding.title} — {finding.principal or finding.resource} "
                f"(covered by {finding.suppressed_by})"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _render_finding(finding: Finding) -> list[str]:
    lines = [f"### `{finding.rule_id}` {finding.title}", ""]
    if finding.principal:
        lines.append(f"- **Principal:** `{finding.principal}`")
    if finding.role:
        lines.append(f"- **Role:** `{finding.role}`")
    lines.append(f"- **Resource:** `{finding.resource}`")
    lines.append(f"- **What we found:** {finding.detail}")
    lines.append(f"- **Fix:** {finding.recommendation}")
    if finding.controls:
        lines.append(f"- **Controls:** {', '.join(finding.controls)}")
    lines.append("")
    return lines


def campaign_to_markdown(campaign: Campaign) -> str:
    """Render the reviewer-facing view of a UAR campaign."""
    lines = [
        f"# {campaign.name}",
        "",
        f"- **Due:** {campaign.due_date}",
        f"- **Entitlements in scope:** {len(campaign.items)}",
        f"- **Reviewer routing coverage:** {campaign.coverage:.0%}",
        f"- **Privileged entitlements:** {sum(1 for i in campaign.items if i.privileged)}",
        "",
        "## Workload by reviewer",
        "",
        "| Reviewer | Items |",
        "| --- | ---: |",
    ]
    for reviewer, count in campaign.reviewers.items():
        lines.append(f"| {reviewer} | {count} |")
    lines += [
        "",
        "## Review worklist",
        "",
        "| Reviewer | Principal | Role | Resource | Privileged | Time-bound | Notes | Decision |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in campaign.items:
        row = item.to_row()
        lines.append(
            "| {reviewer} | `{principal}` | `{role}` | `{resource}` | {privileged} | "
            "{time_bound} | {notes} | {decision} |".format(**row)
        )
    lines.append("")

    if campaign.findings:
        lines += [
            "## Exceptions raised while building the campaign",
            "",
            "These entitlements should not have survived until review time; they "
            "point at a break in joiner/mover/leaver automation.",
            "",
        ]
        for finding in sorted(campaign.findings, key=lambda f: -int(f.severity)):
            lines.append(
                f"- **{finding.severity.name}** `{finding.rule_id}` "
                f"{finding.title} — `{finding.principal}` on `{finding.resource}`: "
                f"{finding.detail}"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def ropa_to_markdown(records: Sequence[dict[str, str]]) -> str:
    """Render the record of processing activities as a reviewable table."""
    lines = [
        "# Record of Processing Activities (RoPA)",
        "",
        f"_Generated {_dt.datetime.now(_dt.timezone.utc):%Y-%m-%d %H:%M UTC} from the "
        "declared data inventory._",
        "",
        f"- **Processing activities recorded:** {len(records)}",
        "",
        "| Asset | System | Owner | Data categories | Purpose | Legal basis | "
        "Retention | Location | Transfers | Safeguard |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for record in records:
        lines.append(
            "| `{asset_id}` | {system} | {owner} | {categories} | {purpose} | "
            "{legal_basis} | {retention} | {location} | {transfers} | "
            "{safeguard} |".format(**record)
        )
    lines.append("")
    return "\n".join(lines)
