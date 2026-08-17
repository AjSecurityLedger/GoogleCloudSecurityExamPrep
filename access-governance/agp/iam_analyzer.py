"""Least-privilege analysis of Google Cloud IAM allow policies.

Input is whatever ``gcloud ... get-iam-policy --format=json`` produces, either a
single policy document or a bundle of them::

    {"resources": [{"name": "projects/prod", "policy": {"bindings": [...]}}]}

Every rule here answers a question a real access-governance programme has to
answer for an auditor: who can reach this resource, why, for how long, and who
said yes.
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any, Iterable

from .models import Binding, Condition, Entitlement, Finding, Principal, Severity
from .policy import GovernancePolicy

CONTROL_REFS = {
    "public": ("CIS-GCP 1.x", "NIST AC-3", "ISO 27001 A.5.15"),
    "least_privilege": ("NIST AC-6", "ISO 27001 A.8.2", "SOC 2 CC6.1"),
    "external": ("NIST AC-2(1)", "SOC 2 CC6.2"),
    "time_bound": ("NIST AC-2(11)", "SOC 2 CC6.3"),
    "sod": ("NIST AC-5", "ISO 27001 A.5.3", "SOC 2 CC5.2"),
    "hygiene": ("NIST AC-2(3)", "SOC 2 CC6.2"),
}


def load_policies(path: "str | Path") -> list[Binding]:
    """Read an IAM policy file and flatten it into bindings."""
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    return parse_policy_document(document)


def parse_policy_document(document: Any) -> list[Binding]:
    """Flatten one or many IAM allow policies into a list of bindings."""
    resources: list[tuple[str, dict[str, Any]]] = []

    if isinstance(document, dict) and "resources" in document:
        for entry in document["resources"]:
            name = entry.get("name") or entry.get("resource") or "(unnamed resource)"
            resources.append((name, entry.get("policy") or entry))
    elif isinstance(document, list):
        for entry in document:
            name = entry.get("name") or entry.get("resource") or "(unnamed resource)"
            resources.append((name, entry.get("policy") or entry))
    elif isinstance(document, dict):
        name = document.get("name") or document.get("resource") or "(unnamed resource)"
        resources.append((name, document))
    else:
        raise ValueError("unsupported IAM policy document: expected object or array")

    bindings: list[Binding] = []
    for resource, policy in resources:
        for raw in policy.get("bindings", []) or []:
            role = raw.get("role", "")
            members = tuple(Principal.parse(m) for m in raw.get("members", []) or [])
            raw_condition = raw.get("condition") or None
            condition = (
                Condition(
                    title=raw_condition.get("title", ""),
                    description=raw_condition.get("description", ""),
                    expression=raw_condition.get("expression", ""),
                )
                if raw_condition
                else None
            )
            bindings.append(
                Binding(
                    resource=resource,
                    role=role,
                    members=members,
                    condition=condition,
                )
            )
    return bindings


def to_entitlements(bindings: Iterable[Binding]) -> list[Entitlement]:
    """Explode bindings into one row per principal — the unit humans review."""
    return [
        Entitlement(
            resource=b.resource,
            role=b.role,
            principal=member,
            condition=b.condition,
        )
        for b in bindings
        for member in b.members
    ]


class IamAnalyzer:
    """Applies the governance policy to a set of IAM bindings."""

    def __init__(
        self,
        policy: "GovernancePolicy | None" = None,
        now: "_dt.datetime | None" = None,
    ) -> None:
        self.policy = policy or GovernancePolicy()
        self.now = now or _dt.datetime.now(_dt.timezone.utc)

    # -- entry point -------------------------------------------------------
    def analyze(self, bindings: Iterable[Binding]) -> list[Finding]:
        entitlements = to_entitlements(bindings)
        findings: list[Finding] = []
        for ent in entitlements:
            findings.extend(self._check_entitlement(ent))
        findings.extend(self._check_sod(entitlements))
        return sorted(
            (self._apply_exemptions(f) for f in findings),
            key=lambda f: (f.is_suppressed, -int(f.severity), f.rule_id, f.resource),
        )

    # -- per-entitlement rules --------------------------------------------
    def _check_entitlement(self, ent: Entitlement) -> list[Finding]:
        principal, role = ent.principal, ent.role
        findings: list[Finding] = []

        def add(rule_id: str, severity: Severity, title: str, detail: str,
                recommendation: str, controls: tuple[str, ...]) -> None:
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    resource=ent.resource,
                    principal=principal.raw,
                    role=role,
                    detail=detail,
                    recommendation=recommendation,
                    controls=controls,
                )
            )

        # IAM001 — anonymous or any-Google-account access.
        if principal.is_public:
            writable = self.policy.is_privileged(role) or not _is_read_only(role)
            add(
                "IAM001",
                Severity.CRITICAL if writable else Severity.HIGH,
                "Resource is exposed to the public internet",
                f"{principal.identifier} holds {role}. Anyone "
                + (
                    "with any Google account"
                    if principal.identifier == "allAuthenticatedUsers"
                    else "on the internet, unauthenticated,"
                )
                + " inherits this access.",
                "Remove the public binding and enforce the Domain Restricted "
                "Sharing org policy (constraints/iam.allowedPolicyMemberDomains).",
                CONTROL_REFS["public"],
            )

        # IAM002 — primitive roles defeat least privilege.
        primitive = self.policy.primitive_severity(role)
        if primitive is not None and primitive >= Severity.MEDIUM:
            severity = primitive
            if self.policy.is_break_glass(principal.raw):
                severity = Severity(max(int(Severity.MEDIUM), int(primitive) - 1))
            add(
                "IAM002",
                severity,
                "Primitive role granted",
                f"{principal.raw} holds the primitive role {role}, which spans "
                "every API in the resource and cannot be scoped.",
                "Replace with predefined or custom roles derived from 90 days of "
                "Policy Analyzer / Recommender usage data.",
                CONTROL_REFS["least_privilege"],
            )

        # IAM003 — identities outside the organisation.
        if self.policy.is_external(principal.domain) and not principal.is_public:
            severity = (
                Severity.CRITICAL
                if self.policy.is_privileged(role)
                else Severity.HIGH
            )
            add(
                "IAM003",
                severity,
                "External identity holds access",
                f"{principal.raw} belongs to {principal.domain}, which is not a "
                f"trusted domain for {self.policy.organization}.",
                "Move third parties to a dedicated project with a time-bound, "
                "condition-scoped grant, and record the contract owner.",
                CONTROL_REFS["external"],
            )

        # IAM004 — standing privilege that should be time-boxed.
        if self.policy.requires_condition(role):
            expires = ent.condition.expires_at if ent.condition else None
            if ent.condition is None or expires is None:
                add(
                    "IAM004",
                    Severity.MEDIUM,
                    "Highly privileged role granted without a time bound",
                    f"{role} on {ent.resource} is a standing grant: the binding "
                    "carries no request.time IAM condition.",
                    "Grant this role just-in-time via Privileged Access Manager, "
                    "or attach a request.time < timestamp(...) condition.",
                    CONTROL_REFS["time_bound"],
                )
            elif expires < self.now:
                add(
                    "IAM009",
                    Severity.LOW,
                    "Expired conditional binding left in place",
                    f"The IAM condition on {role} expired at "
                    f"{expires.isoformat()} but the binding is still present.",
                    "Delete expired bindings; they inflate the review population "
                    "and mask genuinely active access.",
                    CONTROL_REFS["hygiene"],
                )

        # IAM005 — non-human identities with broad power.
        if (
            principal.is_service_account
            and not principal.is_google_managed_sa
            and (primitive is not None or self.policy.is_privileged(role))
        ):
            add(
                "IAM005",
                Severity.HIGH,
                "Service account holds a highly privileged role",
                f"{principal.identifier} runs workloads with {role}. Any workload "
                "able to impersonate it inherits that power.",
                "Scope the service account to a single workload, replace keys with "
                "Workload Identity Federation, and restrict "
                "roles/iam.serviceAccountTokenCreator on it.",
                CONTROL_REFS["least_privilege"],
            )

        # IAM006 — bindings that outlived the identity.
        if principal.deleted:
            add(
                "IAM006",
                Severity.MEDIUM,
                "Binding references a deleted principal",
                f"{principal.raw} no longer exists but still appears in the "
                "allow policy; recreating the identity can silently restore access.",
                "Remove the stale binding as part of leaver processing.",
                CONTROL_REFS["hygiene"],
            )

        # IAM008 — humans should inherit access from groups.
        if (
            principal.is_human
            and self.policy.get("human_access.require_group_bindings", True)
            and not self.policy.is_break_glass(principal.raw)
        ):
            add(
                "IAM008",
                Severity.parse(
                    self.policy.get("human_access.direct_binding_severity", "LOW")
                ),
                "Direct user binding instead of group-based access",
                f"{principal.identifier} is bound directly to {role}, so this "
                "access is invisible to group-driven joiner/mover/leaver automation.",
                "Grant the role to a Cloud Identity group and manage membership "
                "there, so deprovisioning has one control point.",
                CONTROL_REFS["hygiene"],
            )

        return findings

    # -- cross-entitlement rules ------------------------------------------
    def _check_sod(self, entitlements: Iterable[Entitlement]) -> list[Finding]:
        by_principal: dict[str, set[tuple[str, str]]] = {}
        for ent in entitlements:
            by_principal.setdefault(ent.principal.raw, set()).add(
                (ent.role, ent.resource)
            )

        findings: list[Finding] = []
        for conflict in self.policy.sod_conflicts:
            left = set(conflict.get("left", []))
            right = set(conflict.get("right", []))
            for member, grants in sorted(by_principal.items()):
                roles = {role for role, _ in grants}
                hit_left = sorted(roles & left)
                hit_right = sorted(roles & right)
                if not (hit_left and hit_right):
                    continue
                resources = sorted({res for role, res in grants if role in roles})
                findings.append(
                    Finding(
                        rule_id="IAM007",
                        severity=Severity.HIGH,
                        title=f"Segregation of duties conflict: {conflict.get('name', 'unnamed')}",
                        resource=", ".join(resources),
                        principal=member,
                        role=", ".join(hit_left + hit_right),
                        detail=(
                            f"{member} holds {', '.join(hit_left)} and "
                            f"{', '.join(hit_right)}. "
                            + str(conflict.get("rationale", ""))
                        ).strip(),
                        recommendation=(
                            "Split the duties across two principals, or route the "
                            "second role through an approved break-glass workflow."
                        ),
                        controls=CONTROL_REFS["sod"],
                    )
                )
        return findings

    # -- exceptions --------------------------------------------------------
    def _apply_exemptions(self, finding: Finding) -> Finding:
        for exemption in self.policy.exemptions:
            if not exemption.matches(
                finding.rule_id, finding.principal, finding.role, finding.resource
            ):
                continue
            if exemption.is_expired(self.now):
                finding.detail += (
                    f" Exception {exemption.ticket} covering this finding expired on "
                    f"{exemption.expires or '(no end date)'} and is no longer valid."
                )
                continue
            finding.suppressed_by = exemption.label
            break
        return finding


_READ_ONLY_SUFFIXES = ("viewer", "reader", "objectviewer", "get", "list")


def _is_read_only(role: str) -> bool:
    tail = role.rsplit(".", 1)[-1].lower()
    return tail.endswith(_READ_ONLY_SUFFIXES)
