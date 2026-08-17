"""User access review (UAR) campaign generation.

Turns a raw IAM allow policy plus the HR roster into the two things a periodic
access review actually needs: a work list routed to an accountable reviewer,
and the joiner/mover/leaver exceptions that should never have survived until
review time.
"""

from __future__ import annotations

import csv
import datetime as _dt
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .models import Employee, Entitlement, Finding, Severity
from .policy import GovernancePolicy

UNASSIGNED = "UNASSIGNED"


@dataclass
class ReviewItem:
    """One decision a reviewer has to make."""

    reviewer: str
    principal: str
    principal_type: str
    role: str
    resource: str
    privileged: bool
    time_bound: bool
    notes: str = ""
    decision: str = "PENDING"

    def to_row(self) -> dict[str, str]:
        return {
            "reviewer": self.reviewer,
            "principal": self.principal,
            "principal_type": self.principal_type,
            "role": self.role,
            "resource": self.resource,
            "privileged": "yes" if self.privileged else "no",
            "time_bound": "yes" if self.time_bound else "no",
            "notes": self.notes,
            "decision": self.decision,
        }


@dataclass
class Campaign:
    """A generated review campaign plus the findings raised while building it."""

    name: str
    due_date: str
    items: list[ReviewItem] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def reviewers(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.items:
            counts[item.reviewer] = counts.get(item.reviewer, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    @property
    def coverage(self) -> float:
        """Share of items routed to a named reviewer rather than UNASSIGNED."""
        if not self.items:
            return 1.0
        routed = sum(1 for i in self.items if i.reviewer != UNASSIGNED)
        return routed / len(self.items)

    def write_csv(self, path: "str | Path") -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = list(ReviewItem(UNASSIGNED, "", "", "", "", False, False).to_row())
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for item in self.items:
                writer.writerow(item.to_row())
        return path


class AccessReviewBuilder:
    """Builds a review campaign from entitlements and the HR roster."""

    def __init__(
        self,
        policy: "GovernancePolicy | None" = None,
        roster: "dict[str, Employee] | None" = None,
        now: "_dt.datetime | None" = None,
    ) -> None:
        self.policy = policy or GovernancePolicy()
        self.roster = roster or {}
        self.now = now or _dt.datetime.now(_dt.timezone.utc)

    def build(self, entitlements: Iterable[Entitlement], name: str = "") -> Campaign:
        cadence = int(self.policy.get("review.cadence_days", 90) or 90)
        due = self.now + _dt.timedelta(days=cadence)
        campaign = Campaign(
            name=name or f"UAR {self.now:%Y-%m-%d}",
            due_date=f"{due:%Y-%m-%d}",
        )

        for ent in entitlements:
            principal = ent.principal
            if principal.is_google_managed_sa:
                continue  # Google's own agents are out of scope for human review.
            if principal.is_public:
                campaign.findings.append(
                    _finding(
                        "UAR004",
                        Severity.CRITICAL,
                        "Public binding cannot be attested",
                        ent,
                        f"{principal.identifier} has no accountable owner, so no "
                        "reviewer can attest to this access.",
                        "Remove before the campaign opens; public access is never "
                        "a reviewable entitlement.",
                    )
                )
                continue

            reviewer, notes = self._route(ent)
            campaign.findings.extend(self._jml_findings(ent))
            campaign.items.append(
                ReviewItem(
                    reviewer=reviewer,
                    principal=principal.raw,
                    principal_type=principal.kind,
                    role=ent.role,
                    resource=ent.resource,
                    privileged=self.policy.is_privileged(ent.role),
                    time_bound=bool(ent.condition and ent.condition.expires_at),
                    notes=notes,
                )
            )

        campaign.items.sort(
            key=lambda i: (i.reviewer == UNASSIGNED, i.reviewer, i.principal, i.role)
        )
        if campaign.coverage < 1.0:
            unrouted = sum(1 for i in campaign.items if i.reviewer == UNASSIGNED)
            campaign.findings.append(
                Finding(
                    rule_id="UAR003",
                    severity=Severity.MEDIUM,
                    title="Entitlements with no accountable reviewer",
                    resource="(campaign)",
                    detail=f"{unrouted} of {len(campaign.items)} entitlements could "
                    "not be routed: the principal has no manager in the roster and "
                    "no owner is recorded in review.service_account_owners.",
                    recommendation="Record an owner for every service account and "
                    "group; an unowned entitlement is an unreviewable one.",
                    controls=("NIST AC-2(j)", "SOC 2 CC6.2"),
                )
            )
        return campaign

    # -- routing -----------------------------------------------------------
    def _route(self, ent: Entitlement) -> tuple[str, str]:
        principal = ent.principal
        default = str(self.policy.get("review.default_reviewer", "") or "")
        owners = self.policy.get("review.service_account_owners", {}) or {}

        if principal.is_human:
            employee = self.roster.get(principal.identifier.lower())
            if employee and employee.manager_email:
                note = "" if employee.is_active else f"HR status: {employee.status}"
                return employee.manager_email, note
            if employee:
                return default or UNASSIGNED, "No manager recorded in the roster"
            return default or UNASSIGNED, "Principal not found in the HR roster"

        owner = owners.get(principal.identifier) or owners.get(principal.raw)
        if owner:
            return str(owner), ""
        return (default or UNASSIGNED), f"No recorded owner for this {principal.kind}"

    # -- joiner / mover / leaver -------------------------------------------
    def _jml_findings(self, ent: Entitlement) -> list[Finding]:
        principal = ent.principal
        if not principal.is_human or not self.roster:
            return []

        employee = self.roster.get(principal.identifier.lower())
        if employee is None:
            return [
                _finding(
                    "UAR001",
                    Severity.CRITICAL if self.policy.is_privileged(ent.role) else Severity.HIGH,
                    "Orphaned entitlement: identity is not in the HR roster",
                    ent,
                    f"{principal.identifier} holds {ent.role} but has no record in "
                    "the authoritative identity source.",
                    "Reconcile against HR; revoke if the identity cannot be tied to "
                    "an employed person or an approved third party.",
                )
            ]

        findings: list[Finding] = []
        if not employee.is_active:
            findings.append(
                _finding(
                    "UAR002",
                    Severity.CRITICAL,
                    "Leaver retains access",
                    ent,
                    f"{employee.email} has HR status '{employee.status}' but still "
                    f"holds {ent.role}. Deprovisioning did not complete.",
                    "Revoke immediately and fix the leaver automation gap; measure "
                    "time-to-revoke as a control metric.",
                )
            )
        if employee.is_contractor and self.policy.is_privileged(ent.role):
            findings.append(
                _finding(
                    "UAR005",
                    Severity.HIGH,
                    "Contractor holds a privileged role",
                    ent,
                    f"{employee.email} is a {employee.employment_type} with "
                    f"{ent.role}.",
                    "Time-box third-party privilege to the engagement and require "
                    "an internal sponsor to re-approve at each review cycle.",
                )
            )
        return findings


def _finding(
    rule_id: str,
    severity: Severity,
    title: str,
    ent: Entitlement,
    detail: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        resource=ent.resource,
        principal=ent.principal.raw,
        role=ent.role,
        detail=detail,
        recommendation=recommendation,
        controls=("NIST AC-2", "ISO 27001 A.5.18", "SOC 2 CC6.2"),
    )
