import datetime as dt

import pytest

from agp.iam_analyzer import IamAnalyzer, load_policies, parse_policy_document, to_entitlements
from agp.models import Severity
from agp.policy import GovernancePolicy


def analyze(document, policy=None, now=None):
    bindings = parse_policy_document(document)
    return IamAnalyzer(policy or _policy(), now=now).analyze(bindings)


def _policy(**overrides):
    raw = {
        "organization": "test-org",
        "trusted_domains": ["ajsecurityledger.com"],
        "review": {"default_reviewer": "sec@ajsecurityledger.com"},
    }
    raw.update(overrides)
    base = GovernancePolicy()
    base.raw = {**base.raw, **raw}
    return base


def rules(findings):
    return {f.rule_id for f in findings if not f.is_suppressed}


def only(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


def test_parses_single_policy_and_bundle():
    single = {"bindings": [{"role": "roles/viewer", "members": ["allUsers"]}]}
    bundle = {"resources": [{"name": "projects/p", "policy": single}]}
    assert len(parse_policy_document(single)) == 1
    assert parse_policy_document(bundle)[0].resource == "projects/p"
    with pytest.raises(ValueError):
        parse_policy_document("nope")


def test_public_write_binding_is_critical_and_read_is_high():
    write = analyze({"bindings": [{"role": "roles/storage.admin", "members": ["allUsers"]}]})
    read = analyze(
        {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}
    )
    assert only(write, "IAM001")[0].severity is Severity.CRITICAL
    assert only(read, "IAM001")[0].severity is Severity.HIGH


def test_primitive_owner_is_critical_but_softened_for_break_glass():
    policy = _policy(break_glass={"principals": ["user:bg@ajsecurityledger.com"]})
    findings = analyze(
        {
            "bindings": [
                {
                    "role": "roles/owner",
                    "members": [
                        "user:dana@ajsecurityledger.com",
                        "user:bg@ajsecurityledger.com",
                    ],
                }
            ]
        },
        policy=policy,
    )
    by_principal = {f.principal: f for f in only(findings, "IAM002")}
    assert by_principal["user:dana@ajsecurityledger.com"].severity is Severity.CRITICAL
    assert by_principal["user:bg@ajsecurityledger.com"].severity is Severity.HIGH


def test_viewer_is_not_reported_as_a_primitive_violation():
    findings = analyze(
        {"bindings": [{"role": "roles/viewer", "members": ["group:eng@ajsecurityledger.com"]}]}
    )
    assert "IAM002" not in rules(findings)


def test_external_identity_flagged_and_privilege_escalates_severity():
    findings = analyze(
        {
            "bindings": [
                {
                    "role": "roles/secretmanager.admin",
                    "members": ["user:sam@northwind-partners.example"],
                }
            ]
        }
    )
    assert only(findings, "IAM003")[0].severity is Severity.CRITICAL


def test_google_service_agent_domain_is_not_external():
    findings = analyze(
        {
            "bindings": [
                {
                    "role": "roles/monitoring.viewer",
                    "members": [
                        "serviceAccount:service-1@compute-system.iam.gserviceaccount.com"
                    ],
                }
            ]
        }
    )
    assert "IAM003" not in rules(findings)


def test_standing_privileged_role_needs_a_time_bound():
    findings = analyze(
        {
            "bindings": [
                {
                    "role": "roles/cloudkms.admin",
                    "members": ["user:dana@ajsecurityledger.com"],
                }
            ]
        }
    )
    assert "IAM004" in rules(findings)


def test_unexpired_condition_satisfies_the_time_bound_rule():
    findings = analyze(
        {
            "bindings": [
                {
                    "role": "roles/cloudkms.admin",
                    "members": ["user:dana@ajsecurityledger.com"],
                    "condition": {
                        "title": "jit",
                        "expression": 'request.time < timestamp("2027-01-01T00:00:00Z")',
                    },
                }
            ]
        },
        now=dt.datetime(2026, 8, 1, tzinfo=dt.timezone.utc),
    )
    assert "IAM004" not in rules(findings)
    assert "IAM009" not in rules(findings)


def test_expired_condition_is_reported_as_stale_hygiene():
    findings = analyze(
        {
            "bindings": [
                {
                    "role": "roles/cloudkms.admin",
                    "members": ["user:dana@ajsecurityledger.com"],
                    "condition": {
                        "title": "jit",
                        "expression": 'request.time < timestamp("2024-01-01T00:00:00Z")',
                    },
                }
            ]
        },
        now=dt.datetime(2026, 8, 1, tzinfo=dt.timezone.utc),
    )
    assert "IAM009" in rules(findings)
    assert "IAM004" not in rules(findings)


def test_deleted_principal_and_service_account_privilege():
    findings = analyze(
        {
            "bindings": [
                {
                    "role": "roles/bigquery.dataOwner",
                    "members": [
                        "serviceAccount:pipeline@proj.iam.gserviceaccount.com",
                        "deleted:user:gone@ajsecurityledger.com?uid=1",
                    ],
                }
            ]
        }
    )
    assert {"IAM005", "IAM006"} <= rules(findings)


def test_sod_conflict_detected_across_resources():
    findings = analyze(
        {
            "resources": [
                {
                    "name": "projects/a",
                    "policy": {
                        "bindings": [
                            {
                                "role": "roles/iam.securityAdmin",
                                "members": ["user:priya@ajsecurityledger.com"],
                            }
                        ]
                    },
                },
                {
                    "name": "projects/b",
                    "policy": {
                        "bindings": [
                            {
                                "role": "roles/logging.admin",
                                "members": ["user:priya@ajsecurityledger.com"],
                            }
                        ]
                    },
                },
            ]
        }
    )
    conflicts = only(findings, "IAM007")
    assert len(conflicts) == 1
    assert conflicts[0].principal == "user:priya@ajsecurityledger.com"


def test_direct_user_binding_reported_when_group_access_is_required():
    findings = analyze(
        {
            "bindings": [
                {
                    "role": "roles/bigquery.dataViewer",
                    "members": [
                        "user:rae@ajsecurityledger.com",
                        "group:analysts@ajsecurityledger.com",
                    ],
                }
            ]
        }
    )
    direct = only(findings, "IAM008")
    assert [f.principal for f in direct] == ["user:rae@ajsecurityledger.com"]


def test_unexpired_exemption_suppresses_but_expired_one_does_not():
    binding = {
        "resources": [
            {
                "name": "projects/p",
                "policy": {
                    "bindings": [
                        {
                            "role": "roles/bigquery.dataOwner",
                            "members": [
                                "serviceAccount:pipeline@proj.iam.gserviceaccount.com"
                            ],
                        }
                    ]
                },
            }
        ]
    }
    now = dt.datetime(2026, 8, 1, tzinfo=dt.timezone.utc)

    live = _policy(
        exemptions=[
            {
                "ticket": "SEC-1",
                "rule_id": "IAM005",
                "principal": "serviceAccount:pipeline@proj.iam.gserviceaccount.com",
                "role": "*",
                "resource": "*",
                "expires": "2027-01-01T00:00:00Z",
            }
        ]
    )
    expired = _policy(
        exemptions=[
            {
                "ticket": "SEC-1",
                "rule_id": "IAM005",
                "principal": "*",
                "expires": "2025-01-01T00:00:00Z",
            }
        ]
    )

    suppressed = only(analyze(binding, policy=live, now=now), "IAM005")[0]
    still_open = only(analyze(binding, policy=expired, now=now), "IAM005")[0]
    assert suppressed.is_suppressed is True
    assert still_open.is_suppressed is False
    assert "expired" in still_open.detail


def test_exemption_without_an_end_date_is_treated_as_expired():
    policy = _policy(
        exemptions=[{"ticket": "SEC-2", "rule_id": "IAM005", "principal": "*"}]
    )
    findings = analyze(
        {
            "bindings": [
                {
                    "role": "roles/storage.admin",
                    "members": ["serviceAccount:p@proj.iam.gserviceaccount.com"],
                }
            ]
        },
        policy=policy,
    )
    assert only(findings, "IAM005")[0].is_suppressed is False


def test_sample_policy_produces_the_expected_headline_findings(samples, policy, now):
    bindings = load_policies(samples / "iam-policy.json")
    findings = IamAnalyzer(policy, now=now).analyze(bindings)

    assert len(to_entitlements(bindings)) == len(
        [m for b in bindings for m in b.members]
    )
    found = rules(findings)
    # Public exposure, primitive roles, an external contractor, a leftover
    # deleted principal and a segregation-of-duties clash all live in the sample.
    assert {"IAM001", "IAM002", "IAM003", "IAM006", "IAM007"} <= found
    # The terraform runner is covered by an accepted, unexpired exception.
    suppressed = [f for f in findings if f.is_suppressed]
    assert any("terraform-runner" in f.principal for f in suppressed)
    # Findings are ordered most severe first, with suppressed ones last.
    assert findings[0].severity is Severity.CRITICAL
    assert findings[-1].is_suppressed is True
