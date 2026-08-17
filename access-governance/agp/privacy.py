"""Privacy engineering checks over a declared data inventory.

The inventory is the control surface: if an asset holding personal data is not
in it, nothing downstream — retention, DSAR fulfilment, residency, encryption —
can be guaranteed. These rules turn that inventory into findings and into an
Article 30 style record of processing activities (RoPA).
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path
from typing import Any, Iterable

from .models import DataAsset, Finding, Principal, Severity, parse_timestamp
from .policy import GovernancePolicy

PRIVACY_CONTROLS = {
    "encryption": ("GDPR Art. 32", "NIST SC-28", "ISO 27701 A.8.2"),
    "retention": ("GDPR Art. 5(1)(e)", "ISO 27701 A.7.4.7"),
    "lawfulness": ("GDPR Art. 6", "GDPR Art. 30", "ISO 27701 A.7.2"),
    "residency": ("GDPR Ch. V", "NIST SA-9"),
    "rights": ("GDPR Art. 15-17", "ISO 27701 A.7.3"),
    "discovery": ("GDPR Art. 30", "NIST RA-2"),
    "access": ("GDPR Art. 32", "NIST AC-3"),
}


def load_inventory(path: "str | Path") -> list[DataAsset]:
    """Load the data inventory from YAML (or JSON, which YAML is a superset of)."""
    try:
        import yaml
    except ModuleNotFoundError as exc:  # pragma: no cover - env dependent
        raise RuntimeError(
            "PyYAML is required to read the data inventory: pip install pyyaml"
        ) from exc
    with open(path, encoding="utf-8") as handle:
        document = yaml.safe_load(handle) or {}
    return parse_inventory(document)


def parse_inventory(document: Any) -> list[DataAsset]:
    if isinstance(document, dict):
        rows = document.get("assets", [])
    elif isinstance(document, list):
        rows = document
    else:
        raise ValueError("data inventory must be a mapping with 'assets' or a list")
    if not isinstance(rows, list):
        raise ValueError("'assets' must be a list")
    return [DataAsset.from_dict(row) for row in rows]


class PrivacyAnalyzer:
    def __init__(
        self,
        policy: "GovernancePolicy | None" = None,
        now: "_dt.datetime | None" = None,
    ) -> None:
        self.policy = policy or GovernancePolicy()
        self.now = now or _dt.datetime.now(_dt.timezone.utc)

    # -- configuration -----------------------------------------------------
    @property
    def restricted(self) -> tuple[str, ...]:
        return tuple(
            str(c).lower()
            for c in (self.policy.get("privacy.restricted_categories", []) or [])
        )

    @property
    def allowed_locations(self) -> tuple[str, ...]:
        return tuple(
            str(loc).lower()
            for loc in (self.policy.get("privacy.allowed_locations", []) or [])
        )

    # -- entry point -------------------------------------------------------
    def analyze(self, assets: Iterable[DataAsset]) -> list[Finding]:
        findings: list[Finding] = []
        for asset in assets:
            findings.extend(self._check_asset(asset))
        return sorted(findings, key=lambda f: (-int(f.severity), f.rule_id, f.resource))

    def _check_asset(self, asset: DataAsset) -> list[Finding]:
        findings: list[Finding] = []
        personal = asset.holds_personal_data
        restricted = asset.has_category(self.restricted) if self.restricted else False

        def add(rule_id, severity, title, detail, recommendation, controls) -> None:
            findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    resource=f"{asset.asset_id} ({asset.system})",
                    detail=detail,
                    recommendation=recommendation,
                    controls=controls,
                )
            )

        # PRV001 — restricted data must be under customer-managed keys.
        if restricted and asset.encryption.lower() not in ("cmek", "customer-managed"):
            add(
                "PRV001",
                Severity.HIGH,
                "Restricted data without customer-managed encryption",
                f"{asset.asset_id} holds {', '.join(asset.data_categories)} but is "
                f"encrypted with '{asset.encryption}', so key access cannot be "
                "revoked or independently audited.",
                "Move to CMEK in Cloud KMS with rotation and a separate key admin, "
                "and enforce constraints/gcp.restrictNonCmekServices.",
                PRIVACY_CONTROLS["encryption"],
            )

        # PRV002 / PRV003 — storage limitation.
        max_retention = int(self.policy.get("privacy.max_retention_days", 2555) or 2555)
        if personal and asset.retention_days is None:
            add(
                "PRV003",
                Severity.MEDIUM,
                "Personal data held without a retention period",
                f"{asset.asset_id} has no declared retention_days, so data is "
                "retained indefinitely by default.",
                "Declare a retention period tied to the processing purpose and "
                "enforce it (BigQuery table expiration, GCS lifecycle rules).",
                PRIVACY_CONTROLS["retention"],
            )
        elif personal and asset.retention_days is not None:
            if asset.retention_days > max_retention:
                add(
                    "PRV003",
                    Severity.MEDIUM,
                    "Retention period exceeds the organisational maximum",
                    f"{asset.asset_id} declares {asset.retention_days} days, above "
                    f"the {max_retention}-day ceiling.",
                    "Shorten the period or record the legal obligation that "
                    "justifies the longer hold.",
                    PRIVACY_CONTROLS["retention"],
                )
            if (
                asset.oldest_record_days is not None
                and asset.oldest_record_days > asset.retention_days
            ):
                overdue = asset.oldest_record_days - asset.retention_days
                add(
                    "PRV002",
                    Severity.HIGH,
                    "Retention breach: data held past its declared period",
                    f"{asset.asset_id} holds records {asset.oldest_record_days} days "
                    f"old against a {asset.retention_days}-day policy — "
                    f"{overdue} days overdue.",
                    "Run the deletion job, then automate it so the declared period "
                    "is enforced rather than asserted.",
                    PRIVACY_CONTROLS["retention"],
                )

        # PRV004 — lawfulness and purpose limitation.
        missing = [
            field
            for field, value in (("purpose", asset.purpose), ("legal_basis", asset.legal_basis))
            if not str(value).strip()
        ]
        if personal and missing:
            add(
                "PRV004",
                Severity.MEDIUM,
                "Processing recorded without purpose or legal basis",
                f"{asset.asset_id} is missing: {', '.join(missing)}. The RoPA entry "
                "cannot be completed and the processing cannot be justified.",
                "Record the purpose and lawful basis with the business owner before "
                "the next processing change.",
                PRIVACY_CONTROLS["lawfulness"],
            )

        # PRV005 — data residency.
        if (
            personal
            and self.allowed_locations
            and asset.location
            and asset.location.lower() not in self.allowed_locations
        ):
            add(
                "PRV005",
                Severity.HIGH,
                "Personal data stored outside the approved region",
                f"{asset.asset_id} is located in '{asset.location}', which is not in "
                f"the approved set ({', '.join(self.allowed_locations)}).",
                "Relocate the data and pin the location with "
                "constraints/gcp.resourceLocations on the parent folder.",
                PRIVACY_CONTROLS["residency"],
            )

        # PRV009 — international transfers need a safeguard.
        if personal and asset.transfers:
            safeguards = [
                str(s).lower()
                for s in (
                    self.policy.get("privacy.approved_transfer_safeguards", []) or []
                )
            ]
            if not asset.transfer_safeguard:
                add(
                    "PRV009",
                    Severity.HIGH,
                    "Cross-border transfer without a recorded safeguard",
                    f"{asset.asset_id} transfers personal data to "
                    f"{', '.join(asset.transfers)} with no transfer_safeguard.",
                    "Record the transfer mechanism (adequacy decision, SCCs, BCRs) "
                    "and attach the transfer impact assessment.",
                    PRIVACY_CONTROLS["residency"],
                )
            elif safeguards and asset.transfer_safeguard.lower() not in safeguards:
                add(
                    "PRV009",
                    Severity.MEDIUM,
                    "Transfer safeguard is not an approved mechanism",
                    f"{asset.asset_id} relies on '{asset.transfer_safeguard}', which "
                    "is not in the approved list.",
                    "Replace with an approved mechanism or seek privacy counsel "
                    "sign-off and add it to the policy.",
                    PRIVACY_CONTROLS["residency"],
                )

        # PRV006 — data subject rights must be technically reachable.
        if personal and not asset.subject_key:
            add(
                "PRV006",
                Severity.HIGH,
                "Data subject requests cannot be fulfilled for this asset",
                f"{asset.asset_id} holds personal data but declares no subject_key, "
                "so records cannot be located for access, rectification or erasure.",
                "Add a stable subject identifier (or a documented join path) and "
                "cover the asset in the DSAR runbook.",
                PRIVACY_CONTROLS["rights"],
            )

        # PRV007 — discovery must be current.
        max_age = int(self.policy.get("privacy.max_dlp_scan_age_days", 90) or 90)
        scanned = parse_timestamp(asset.last_dlp_scan)
        if personal and scanned is None:
            add(
                "PRV007",
                Severity.MEDIUM,
                "Asset has never been scanned for sensitive data",
                f"{asset.asset_id} has no last_dlp_scan, so the declared categories "
                "are unverified.",
                "Schedule a Sensitive Data Protection (Cloud DLP) inspection job and "
                "reconcile the findings against the declared categories.",
                PRIVACY_CONTROLS["discovery"],
            )
        elif personal and scanned is not None:
            age = (self.now - scanned).days
            if age > max_age:
                add(
                    "PRV007",
                    Severity.LOW,
                    "Sensitive-data scan is stale",
                    f"{asset.asset_id} was last scanned {age} days ago, beyond the "
                    f"{max_age}-day threshold.",
                    "Automate recurring inspection so the inventory stays true "
                    "between reviews.",
                    PRIVACY_CONTROLS["discovery"],
                )

        # PRV008 — every asset needs an accountable owner.
        if not asset.owner:
            add(
                "PRV008",
                Severity.LOW,
                "Data asset has no accountable owner",
                f"{asset.asset_id} has no owner, so no one can approve access or "
                "attest to its retention.",
                "Assign a named data owner; unowned data cannot be governed.",
                PRIVACY_CONTROLS["lawfulness"],
            )

        # PRV010 — broad access to personal data.
        for member in asset.access_principals:
            principal = Principal.parse(member)
            if personal and principal.is_public:
                add(
                    "PRV010",
                    Severity.CRITICAL,
                    "Personal data is broadly accessible",
                    f"{asset.asset_id} grants access to {principal.identifier}.",
                    "Remove immediately and check access logs for exposure during "
                    "the window the binding existed.",
                    PRIVACY_CONTROLS["access"],
                )
            elif personal and self.policy.is_external(principal.domain):
                add(
                    "PRV010",
                    Severity.HIGH,
                    "External identity can access personal data",
                    f"{asset.asset_id} is accessible to {principal.raw} from "
                    f"{principal.domain}.",
                    "Confirm the processor agreement covers this access, or revoke.",
                    PRIVACY_CONTROLS["access"],
                )

        return findings


def build_ropa(assets: Iterable[DataAsset]) -> list[dict[str, str]]:
    """Produce Article 30 style records of processing from the inventory."""
    records: list[dict[str, str]] = []
    for asset in assets:
        if not asset.holds_personal_data:
            continue
        records.append(
            {
                "asset_id": asset.asset_id,
                "name": asset.name or asset.asset_id,
                "system": asset.system,
                "owner": asset.owner or "UNASSIGNED",
                "categories": ", ".join(asset.data_categories),
                "purpose": asset.purpose or "NOT RECORDED",
                "legal_basis": asset.legal_basis or "NOT RECORDED",
                "retention": (
                    f"{asset.retention_days} days"
                    if asset.retention_days is not None
                    else "NOT RECORDED"
                ),
                "location": asset.location or "NOT RECORDED",
                "transfers": ", ".join(asset.transfers) or "none",
                "safeguard": asset.transfer_safeguard or "n/a",
            }
        )
    return sorted(records, key=lambda r: r["asset_id"])
