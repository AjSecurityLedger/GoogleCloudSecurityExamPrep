"""Core domain types shared by the access-governance and privacy modules."""

from __future__ import annotations

import csv
import datetime as _dt
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Iterable


class Severity(IntEnum):
    """Ordered severities so findings can be sorted and thresholded."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: "str | Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        try:
            return cls[str(value).strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value!r}") from exc

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


PRINCIPAL_TYPES = (
    "user",
    "serviceAccount",
    "group",
    "domain",
    "principal",
    "principalSet",
    "projectOwner",
    "projectEditor",
    "projectViewer",
)

PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")

# Domains Google reserves for its own service agents.
GOOGLE_AGENT_DOMAINS = frozenset(
    {
        "cloudservices.gserviceaccount.com",
        "appspot.gserviceaccount.com",
        "developer.gserviceaccount.com",
        "container-engine-robot.iam.gserviceaccount.com",
    }
)


@dataclass(frozen=True)
class Principal:
    """A single IAM member string, decomposed into its parts.

    Handles the ``deleted:`` prefix and the ``?uid=`` suffix that Google Cloud
    adds once an identity is removed but its bindings are left behind.
    """

    raw: str
    kind: str
    identifier: str
    deleted: bool = False

    @classmethod
    def parse(cls, member: str) -> "Principal":
        raw = member.strip()
        rest = raw
        deleted = False
        if rest.startswith("deleted:"):
            deleted = True
            rest = rest[len("deleted:") :]
        # Drop the ?uid=... suffix attached to deleted principals.
        rest = rest.split("?uid=", 1)[0]

        if rest in PUBLIC_MEMBERS:
            return cls(raw=raw, kind="public", identifier=rest, deleted=deleted)

        kind, sep, identifier = rest.partition(":")
        if not sep or kind not in PRINCIPAL_TYPES:
            return cls(raw=raw, kind="unknown", identifier=rest, deleted=deleted)
        return cls(raw=raw, kind=kind, identifier=identifier, deleted=deleted)

    @property
    def domain(self) -> str:
        """Domain of the identity, or an empty string when it has none."""
        if self.kind == "domain":
            return self.identifier.lower()
        if "@" in self.identifier:
            return self.identifier.rsplit("@", 1)[1].lower()
        return ""

    @property
    def is_public(self) -> bool:
        return self.kind == "public"

    @property
    def is_human(self) -> bool:
        return self.kind == "user"

    @property
    def is_service_account(self) -> bool:
        return self.kind == "serviceAccount"

    @property
    def is_google_managed_sa(self) -> bool:
        """True for Google's own service agents, which humans cannot review.

        User-managed accounts live at ``<name>@<project-id>.iam.gserviceaccount.com``;
        Google's service agents use reserved project prefixes such as
        ``gcp-sa-storage``, ``compute-system`` and ``cloudservices``.
        """
        if not self.is_service_account:
            return False
        domain = self.domain
        if not domain.endswith("gserviceaccount.com"):
            return False
        if domain in GOOGLE_AGENT_DOMAINS:
            return True
        project = domain.split(".", 1)[0]
        return project.startswith("gcp-sa-") or project.endswith("-system")


@dataclass(frozen=True)
class Condition:
    title: str = ""
    description: str = ""
    expression: str = ""

    @property
    def expires_at(self) -> "_dt.datetime | None":
        """Best-effort extraction of the timestamp in a request.time CEL guard."""
        expr = self.expression
        marker = 'timestamp("'
        idx = expr.find(marker)
        if "request.time" not in expr or idx < 0:
            return None
        end = expr.find('"', idx + len(marker))
        if end < 0:
            return None
        return parse_timestamp(expr[idx + len(marker) : end])


@dataclass(frozen=True)
class Binding:
    """One ``role -> members`` binding, tied back to the resource it came from."""

    resource: str
    role: str
    members: tuple[Principal, ...]
    condition: "Condition | None" = None


@dataclass(frozen=True)
class Entitlement:
    """A single principal's grant of one role on one resource."""

    resource: str
    role: str
    principal: Principal
    condition: "Condition | None" = None

    @property
    def key(self) -> str:
        return f"{self.resource}|{self.role}|{self.principal.raw}"


@dataclass
class Finding:
    """A policy violation produced by one of the analyzers."""

    rule_id: str
    severity: Severity
    title: str
    resource: str
    detail: str
    recommendation: str
    principal: str = ""
    role: str = ""
    controls: tuple[str, ...] = ()
    suppressed_by: str = ""

    @property
    def is_suppressed(self) -> bool:
        return bool(self.suppressed_by)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.name,
            "title": self.title,
            "resource": self.resource,
            "principal": self.principal,
            "role": self.role,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "controls": list(self.controls),
            "suppressed_by": self.suppressed_by,
        }


@dataclass
class Employee:
    """A row from the HR roster, the authoritative source for identity state."""

    email: str
    name: str = ""
    department: str = ""
    manager_email: str = ""
    status: str = "active"
    employment_type: str = "employee"

    @property
    def is_active(self) -> bool:
        return self.status.strip().lower() == "active"

    @property
    def is_contractor(self) -> bool:
        return self.employment_type.strip().lower() in ("contractor", "vendor", "temp")


@dataclass
class DataAsset:
    """One row of the data inventory / record of processing activities."""

    asset_id: str
    name: str = ""
    system: str = ""
    owner: str = ""
    environment: str = "prod"
    data_categories: list[str] = field(default_factory=list)
    purpose: str = ""
    legal_basis: str = ""
    retention_days: "int | None" = None
    oldest_record_days: "int | None" = None
    encryption: str = "google-managed"
    location: str = ""
    transfers: list[str] = field(default_factory=list)
    transfer_safeguard: str = ""
    subject_key: str = ""
    access_principals: list[str] = field(default_factory=list)
    last_dlp_scan: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "DataAsset":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        unknown = set(raw) - known
        if unknown:
            raise ValueError(
                f"data asset {raw.get('asset_id', '<unnamed>')!r} has unknown "
                f"field(s): {', '.join(sorted(unknown))}"
            )
        if "asset_id" not in raw:
            raise ValueError("every data asset needs an 'asset_id'")
        return cls(**raw)

    def has_category(self, prefixes: Iterable[str]) -> bool:
        prefixes = tuple(p.lower() for p in prefixes)
        return any(c.lower().startswith(prefixes) for c in self.data_categories)

    @property
    def holds_personal_data(self) -> bool:
        return self.has_category(("pii", "phi", "pci", "special"))


def parse_timestamp(value: str) -> "_dt.datetime | None":
    """Parse an RFC 3339 timestamp into an aware UTC datetime."""
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc)


def load_roster(path: "str | Path") -> dict[str, Employee]:
    """Load the HR roster CSV, keyed by lower-cased email."""
    roster: dict[str, Employee] = {}
    with open(path, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            email = (row.get("email") or "").strip().lower()
            if not email:
                continue
            roster[email] = Employee(
                email=email,
                name=(row.get("name") or "").strip(),
                department=(row.get("department") or "").strip(),
                manager_email=(row.get("manager_email") or "").strip().lower(),
                status=(row.get("status") or "active").strip(),
                employment_type=(row.get("employment_type") or "employee").strip(),
            )
    return roster
