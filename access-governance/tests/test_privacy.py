import pytest

from agp.models import DataAsset, Severity
from agp.privacy import PrivacyAnalyzer, build_ropa, load_inventory, parse_inventory


BASE = {
    "asset_id": "bq.test.asset",
    "system": "BigQuery",
    "owner": "owner@ajsecurityledger.com",
    "data_categories": ["pii.contact"],
    "purpose": "Testing",
    "legal_basis": "Contract",
    "retention_days": 365,
    "oldest_record_days": 100,
    "encryption": "CMEK",
    "location": "europe-west1",
    "subject_key": "user_id",
    "last_dlp_scan": "2026-07-01T00:00:00Z",
}


def analyze(policy, now, **overrides):
    asset = DataAsset.from_dict({**BASE, **overrides})
    return PrivacyAnalyzer(policy, now=now).analyze([asset])


def rules(findings):
    return {f.rule_id for f in findings}


def test_compliant_asset_produces_no_findings(policy, now):
    assert analyze(policy, now) == []


def test_restricted_data_without_cmek(policy, now):
    findings = analyze(
        policy, now, data_categories=["pii.national_id"], encryption="google-managed"
    )
    assert "PRV001" in rules(findings)


def test_non_restricted_data_without_cmek_is_allowed(policy, now):
    assert "PRV001" not in rules(analyze(policy, now, encryption="google-managed"))


def test_retention_breach_and_missing_retention(policy, now):
    breach = analyze(policy, now, retention_days=365, oldest_record_days=400)
    missing = analyze(policy, now, retention_days=None)
    assert "PRV002" in rules(breach)
    assert "PRV003" in rules(missing)


def test_retention_above_the_ceiling_is_flagged(policy, now):
    findings = analyze(policy, now, retention_days=3650, oldest_record_days=10)
    assert "PRV003" in rules(findings)


def test_missing_purpose_or_legal_basis(policy, now):
    findings = analyze(policy, now, legal_basis="")
    prv004 = [f for f in findings if f.rule_id == "PRV004"]
    assert prv004 and "legal_basis" in prv004[0].detail


def test_location_outside_the_approved_regions(policy, now):
    assert "PRV005" in rules(analyze(policy, now, location="us-central1"))


def test_transfer_requires_an_approved_safeguard(policy, now):
    missing = analyze(policy, now, transfers=["us"])
    unapproved = analyze(policy, now, transfers=["us"], transfer_safeguard="handshake")
    approved = analyze(policy, now, transfers=["us"], transfer_safeguard="SCC")
    assert [f.severity for f in missing if f.rule_id == "PRV009"] == [Severity.HIGH]
    assert [f.severity for f in unapproved if f.rule_id == "PRV009"] == [Severity.MEDIUM]
    assert "PRV009" not in rules(approved)


def test_asset_without_a_subject_key_breaks_dsar_fulfilment(policy, now):
    assert "PRV006" in rules(analyze(policy, now, subject_key=""))


def test_scan_freshness(policy, now):
    never = analyze(policy, now, last_dlp_scan="")
    stale = analyze(policy, now, last_dlp_scan="2025-01-01T00:00:00Z")
    assert [f.severity for f in never if f.rule_id == "PRV007"] == [Severity.MEDIUM]
    assert [f.severity for f in stale if f.rule_id == "PRV007"] == [Severity.LOW]


def test_ownerless_asset(policy, now):
    assert "PRV008" in rules(analyze(policy, now, owner=""))


def test_broad_and_external_access_to_personal_data(policy, now):
    public = analyze(policy, now, access_principals=["allUsers"])
    external = analyze(
        policy, now, access_principals=["user:sam@northwind-partners.example"]
    )
    assert [f.severity for f in public if f.rule_id == "PRV010"] == [Severity.CRITICAL]
    assert [f.severity for f in external if f.rule_id == "PRV010"] == [Severity.HIGH]


def test_assets_without_personal_data_skip_the_privacy_rules(policy, now):
    findings = analyze(
        policy,
        now,
        data_categories=["none"],
        legal_basis="",
        purpose="",
        subject_key="",
        retention_days=None,
        last_dlp_scan="",
        location="us-central1",
    )
    assert rules(findings) == set()


def test_inventory_parsing_rejects_bad_shapes():
    with pytest.raises(ValueError):
        parse_inventory("not an inventory")
    with pytest.raises(ValueError):
        parse_inventory({"assets": {"asset_id": "x"}})
    with pytest.raises(ValueError, match="asset_id"):
        parse_inventory([{"name": "no id"}])


def test_sample_inventory_findings_and_ropa(samples, policy, now):
    assets = load_inventory(samples / "data-inventory.yaml")
    findings = PrivacyAnalyzer(policy, now=now).analyze(assets)
    found = rules(findings)

    # The sample deliberately contains a retention breach, an unencrypted
    # special-category store, a US-hosted asset, an ungoverned event stream and
    # broad access to personal data.
    assert {"PRV001", "PRV002", "PRV003", "PRV004", "PRV005", "PRV006", "PRV010"} <= found
    assert findings[0].severity is Severity.CRITICAL

    ropa = build_ropa(assets)
    ids = [record["asset_id"] for record in ropa]
    assert "bq.finance.ledger" not in ids  # holds no personal data
    assert ids == sorted(ids)
    ungoverned = next(r for r in ropa if r["asset_id"] == "bq.analytics.events_raw")
    assert ungoverned["legal_basis"] == "NOT RECORDED"
    assert ungoverned["owner"] == "UNASSIGNED"
