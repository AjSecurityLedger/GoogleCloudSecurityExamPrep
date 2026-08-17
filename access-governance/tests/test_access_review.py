import csv

from agp.access_review import UNASSIGNED, AccessReviewBuilder
from agp.iam_analyzer import load_policies, parse_policy_document, to_entitlements
from agp.models import Severity, load_roster
from agp.policy import GovernancePolicy


def build(document, policy=None, roster=None, now=None):
    entitlements = to_entitlements(parse_policy_document(document))
    return AccessReviewBuilder(policy, roster, now=now).build(entitlements)


def rules(findings):
    return {f.rule_id for f in findings}


def test_items_route_to_the_managers_of_the_principal(samples, policy, now):
    roster = load_roster(samples / "roster.csv")
    campaign = build(
        {
            "bindings": [
                {
                    "role": "roles/bigquery.dataViewer",
                    "members": ["user:rae.analyst@ajsecurityledger.com"],
                }
            ]
        },
        policy,
        roster,
        now,
    )
    assert campaign.items[0].reviewer == "data-eng-lead@ajsecurityledger.com"
    assert campaign.coverage == 1.0


def test_service_accounts_route_to_their_recorded_owner(policy, now):
    campaign = build(
        {
            "bindings": [
                {
                    "role": "roles/bigquery.dataOwner",
                    "members": [
                        "serviceAccount:data-pipeline@ajsl-analytics.iam.gserviceaccount.com"
                    ],
                }
            ]
        },
        policy,
        {},
        now,
    )
    assert campaign.items[0].reviewer == "data-eng-lead@ajsecurityledger.com"


def test_unowned_principal_falls_back_and_is_flagged(now):
    empty_policy = GovernancePolicy()
    campaign = build(
        {
            "bindings": [
                {
                    "role": "roles/storage.admin",
                    "members": ["serviceAccount:mystery@proj.iam.gserviceaccount.com"],
                }
            ]
        },
        empty_policy,
        {},
        now,
    )
    assert campaign.items[0].reviewer == UNASSIGNED
    assert campaign.coverage == 0.0
    assert "UAR003" in rules(campaign.findings)


def test_leaver_with_live_access_is_critical(samples, policy, now):
    roster = load_roster(samples / "roster.csv")
    campaign = build(
        {
            "bindings": [
                {
                    "role": "roles/compute.admin",
                    "members": ["user:jules.former@ajsecurityledger.com"],
                }
            ]
        },
        policy,
        roster,
        now,
    )
    leaver = [f for f in campaign.findings if f.rule_id == "UAR002"]
    assert leaver and leaver[0].severity is Severity.CRITICAL


def test_identity_missing_from_the_roster_is_an_orphan(samples, policy, now):
    roster = load_roster(samples / "roster.csv")
    campaign = build(
        {
            "bindings": [
                {
                    "role": "roles/storage.admin",
                    "members": ["user:ghost@ajsecurityledger.com"],
                }
            ]
        },
        policy,
        roster,
        now,
    )
    orphan = [f for f in campaign.findings if f.rule_id == "UAR001"]
    assert orphan and orphan[0].severity is Severity.CRITICAL


def test_contractor_with_privileged_role_is_flagged(samples, policy, now):
    roster = load_roster(samples / "roster.csv")
    campaign = build(
        {
            "bindings": [
                {
                    "role": "roles/secretmanager.admin",
                    "members": ["user:sam.contractor@northwind-partners.example"],
                }
            ]
        },
        policy,
        roster,
        now,
    )
    assert "UAR005" in rules(campaign.findings)


def test_public_bindings_are_excluded_from_the_worklist(policy, now):
    campaign = build(
        {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]},
        policy,
        {},
        now,
    )
    assert campaign.items == []
    assert "UAR004" in rules(campaign.findings)


def test_google_service_agents_are_out_of_scope(policy, now):
    campaign = build(
        {
            "bindings": [
                {
                    "role": "roles/monitoring.viewer",
                    "members": [
                        "serviceAccount:service-1@compute-system.iam.gserviceaccount.com"
                    ],
                }
            ]
        },
        policy,
        {},
        now,
    )
    assert campaign.items == []


def test_due_date_follows_the_configured_cadence(policy, now):
    campaign = build(
        {"bindings": [{"role": "roles/viewer", "members": ["group:x@ajsecurityledger.com"]}]},
        policy,
        {},
        now,
    )
    assert campaign.due_date == "2026-10-30"  # 2026-08-01 + 90 days
    assert campaign.name == "UAR 2026-08-01"


def test_campaign_csv_round_trips(tmp_path, samples, policy, now):
    entitlements = to_entitlements(load_policies(samples / "iam-policy.json"))
    roster = load_roster(samples / "roster.csv")
    campaign = AccessReviewBuilder(policy, roster, now=now).build(entitlements)
    path = campaign.write_csv(tmp_path / "campaign" / "worklist.csv")

    with open(path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == len(campaign.items)
    assert {row["decision"] for row in rows} == {"PENDING"}
    assert all(row["reviewer"] for row in rows)
