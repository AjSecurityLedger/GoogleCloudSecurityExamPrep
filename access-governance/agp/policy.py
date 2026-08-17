"""Loading and interpretation of the governance policy (``governance-policy.yaml``).

The policy file is the single place where the organisation's rules live: which
domains are trusted, which roles are privileged, which role pairs break
separation of duties, and which exceptions have been formally accepted.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Severity, parse_timestamp

DEFAULT_POLICY: dict[str, Any] = {
    "organization": "example-org",
    "trusted_domains": [],
    "primitive_roles": {
        "roles/owner": "CRITICAL",
        "roles/editor": "HIGH",
        "roles/viewer": "LOW",
    },
    "privileged_roles": [
        "roles/iam.securityAdmin",
        "roles/iam.serviceAccountKeyAdmin",
        "roles/iam.serviceAccountTokenCreator",
        "roles/iam.workloadIdentityPoolAdmin",
        "roles/resourcemanager.organizationAdmin",
        "roles/resourcemanager.folderAdmin",
        "roles/billing.admin",
        "roles/cloudkms.admin",
        "roles/cloudkms.cryptoKeyDecrypter",
        "roles/logging.admin",
        "roles/bigquery.dataOwner",
        "roles/storage.admin",
        "roles/secretmanager.admin",
    ],
    # Roles that must never sit on a permanent binding: they are time-boxed
    # through an IAM condition or granted just-in-time.
    "requires_condition": [
        "roles/owner",
        "roles/iam.securityAdmin",
        "roles/resourcemanager.organizationAdmin",
        "roles/cloudkms.admin",
        "roles/billing.admin",
    ],
    "sod_conflicts": [
        {
            "name": "Key management vs. data read",
            "left": ["roles/cloudkms.admin", "roles/cloudkms.cryptoKeyDecrypter"],
            "right": ["roles/bigquery.dataViewer", "roles/storage.objectViewer"],
            "rationale": (
                "A principal that both controls the KMS key and can read the "
                "ciphertext can unilaterally exfiltrate protected data."
            ),
        },
        {
            "name": "Grant vs. audit",
            "left": ["roles/iam.securityAdmin", "roles/resourcemanager.projectIamAdmin"],
            "right": ["roles/logging.admin", "roles/logging.configWriter"],
            "rationale": (
                "Whoever can grant themselves access must not also be able to "
                "disable or reconfigure the audit trail that records it."
            ),
        },
        {
            "name": "Spend approval vs. spend creation",
            "left": ["roles/billing.admin"],
            "right": ["roles/compute.admin"],
            "rationale": (
                "Provisioning cost and approving cost are separate duties; a "
                "single holder can hide resource sprawl."
            ),
        },
    ],
    "break_glass": {
        "principals": [],
        "max_hours": 8,
    },
    "human_access": {
        # Human identities should inherit access from groups, not direct
        # bindings, so that joiner/mover/leaver automation has one control point.
        "require_group_bindings": True,
        "direct_binding_severity": "LOW",
    },
    "exemptions": [],
    "review": {
        "cadence_days": 90,
        "default_reviewer": "",
        "service_account_owners": {},
    },
    "privacy": {
        "restricted_categories": ["special", "phi", "pci", "pii.national_id"],
        "allowed_locations": [],
        "approved_transfer_safeguards": ["SCC", "adequacy", "BCR"],
        "max_dlp_scan_age_days": 90,
        "max_retention_days": 2555,
    },
}


@dataclass(frozen=True)
class Exemption:
    """A formally accepted exception to one of the rules."""

    ticket: str
    principal: str = "*"
    role: str = "*"
    resource: str = "*"
    rule_id: str = "*"
    expires: str = ""
    justification: str = ""

    def is_expired(self, now: "_dt.datetime | None" = None) -> bool:
        now = now or _dt.datetime.now(_dt.timezone.utc)
        expiry = parse_timestamp(self.expires)
        if expiry is None:
            # An exception with no end date is not an exception, it is a policy
            # change that never happened. Treat it as expired.
            return True
        return expiry < now

    def matches(self, rule_id: str, principal: str, role: str, resource: str) -> bool:
        return (
            _glob(self.rule_id, rule_id)
            and _glob(self.principal, principal)
            and _glob(self.role, role)
            and _glob(self.resource, resource)
        )

    @property
    def label(self) -> str:
        return f"{self.ticket} (expires {self.expires or 'never'})"


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Merge ``override`` onto ``base``; nested mappings merge, lists replace."""
    merged = dict(base)
    for key, value in override.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


def _glob(pattern: str, value: str) -> bool:
    """Case-insensitive match supporting a single trailing ``*`` wildcard."""
    pattern = (pattern or "*").strip().lower()
    value = (value or "").strip().lower()
    if pattern in ("*", ""):
        return True
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value


@dataclass
class GovernancePolicy:
    raw: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_POLICY))

    @classmethod
    def load(cls, path: "str | Path | None" = None) -> "GovernancePolicy":
        if path is None:
            return cls()
        try:
            import yaml  # imported lazily so JSON-only usage needs no dependency
        except ModuleNotFoundError as exc:  # pragma: no cover - env dependent
            raise RuntimeError(
                "PyYAML is required to read a policy file: pip install pyyaml"
            ) from exc
        with open(path, encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"{path}: policy file must contain a YAML mapping")
        return cls(raw=_deep_merge(DEFAULT_POLICY, loaded))

    # -- generic accessors -------------------------------------------------
    def get(self, path: str, default: Any = None) -> Any:
        node: Any = self.raw
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    # -- identity ----------------------------------------------------------
    @property
    def organization(self) -> str:
        return str(self.get("organization", "example-org"))

    @property
    def trusted_domains(self) -> tuple[str, ...]:
        return tuple(str(d).lower() for d in self.get("trusted_domains", []))

    def is_external(self, domain: str) -> bool:
        """True when a domain is outside the org and not a Google-managed one."""
        if not domain:
            return False
        if domain.endswith("gserviceaccount.com"):
            return False
        if not self.trusted_domains:
            return False
        return domain.lower() not in self.trusted_domains

    # -- roles -------------------------------------------------------------
    def primitive_severity(self, role: str) -> "Severity | None":
        primitives = self.get("primitive_roles", {}) or {}
        if isinstance(primitives, list):  # tolerate a plain list in the YAML
            primitives = {r: "HIGH" for r in primitives}
        if role not in primitives:
            return None
        return Severity.parse(primitives[role])

    def is_privileged(self, role: str) -> bool:
        return role in set(self.get("privileged_roles", []) or []) or (
            self.primitive_severity(role) is not None
            and self.primitive_severity(role) >= Severity.HIGH
        )

    def requires_condition(self, role: str) -> bool:
        return role in set(self.get("requires_condition", []) or [])

    @property
    def sod_conflicts(self) -> list[dict[str, Any]]:
        return list(self.get("sod_conflicts", []) or [])

    # -- exceptions --------------------------------------------------------
    @property
    def exemptions(self) -> list[Exemption]:
        result: list[Exemption] = []
        for item in self.get("exemptions", []) or []:
            if not isinstance(item, dict) or "ticket" not in item:
                raise ValueError("each exemption needs at least a 'ticket' field")
            result.append(Exemption(**item))
        return result

    @property
    def break_glass_principals(self) -> tuple[str, ...]:
        return tuple(
            str(p).lower() for p in (self.get("break_glass.principals", []) or [])
        )

    def is_break_glass(self, member: str) -> bool:
        return member.strip().lower() in self.break_glass_principals
