import pytest

from agp.models import DataAsset, Principal, Severity, load_roster, parse_timestamp


@pytest.mark.parametrize(
    "member,kind,identifier,domain",
    [
        ("user:dana@ajsecurityledger.com", "user", "dana@ajsecurityledger.com", "ajsecurityledger.com"),
        ("group:eng@ajsecurityledger.com", "group", "eng@ajsecurityledger.com", "ajsecurityledger.com"),
        ("domain:ajsecurityledger.com", "domain", "ajsecurityledger.com", "ajsecurityledger.com"),
        ("allUsers", "public", "allUsers", ""),
        ("allAuthenticatedUsers", "public", "allAuthenticatedUsers", ""),
    ],
)
def test_principal_parsing(member, kind, identifier, domain):
    principal = Principal.parse(member)
    assert (principal.kind, principal.identifier, principal.domain) == (
        kind,
        identifier,
        domain,
    )


def test_deleted_principal_strips_prefix_and_uid():
    principal = Principal.parse("deleted:user:gone@ajsecurityledger.com?uid=1039485")
    assert principal.deleted is True
    assert principal.kind == "user"
    assert principal.identifier == "gone@ajsecurityledger.com"


def test_google_service_agents_are_distinguished_from_user_managed_accounts():
    agent = Principal.parse(
        "serviceAccount:service-1@compute-system.iam.gserviceaccount.com"
    )
    workload = Principal.parse(
        "serviceAccount:pipeline@ajsl-analytics.iam.gserviceaccount.com"
    )
    assert agent.is_google_managed_sa is True
    assert workload.is_google_managed_sa is False


def test_severity_is_ordered_and_parsable():
    assert Severity.CRITICAL > Severity.HIGH > Severity.LOW
    assert Severity.parse("high") is Severity.HIGH
    with pytest.raises(ValueError):
        Severity.parse("catastrophic")


def test_parse_timestamp_normalises_to_utc():
    assert parse_timestamp("2026-01-01T00:00:00Z").tzinfo is not None
    assert parse_timestamp("not a date") is None
    assert parse_timestamp("") is None


def test_data_asset_rejects_unknown_fields():
    with pytest.raises(ValueError, match="unknown field"):
        DataAsset.from_dict({"asset_id": "x", "retenion_days": 30})


def test_data_asset_category_matching():
    asset = DataAsset.from_dict(
        {"asset_id": "x", "data_categories": ["pii.national_id"]}
    )
    assert asset.holds_personal_data is True
    assert asset.has_category(["pii.national_id"]) is True
    assert asset.has_category(["phi"]) is False


def test_roster_loads_and_classifies(samples):
    roster = load_roster(samples / "roster.csv")
    assert roster["jules.former@ajsecurityledger.com"].is_active is False
    assert roster["sam.contractor@northwind-partners.example"].is_contractor is True
    assert roster["dana.ops@ajsecurityledger.com"].manager_email == (
        "platform-lead@ajsecurityledger.com"
    )
