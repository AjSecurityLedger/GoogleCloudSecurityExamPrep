import json

import pytest

from agp.cli import main
from agp.models import Finding, Severity
from agp.report import summarize, to_json, to_markdown, worst_severity


def _finding(severity=Severity.HIGH, suppressed=""):
    return Finding(
        rule_id="IAM002",
        severity=severity,
        title="Primitive role granted",
        resource="projects/p",
        detail="detail",
        recommendation="fix it",
        principal="user:a@b.com",
        role="roles/editor",
        controls=("NIST AC-6",),
        suppressed_by=suppressed,
    )


def test_summary_excludes_suppressed_findings():
    findings = [_finding(), _finding(suppressed="SEC-1 (expires 2027-01-01)")]
    assert summarize(findings)["HIGH"] == 1
    assert worst_severity(findings) is Severity.HIGH
    assert worst_severity([_finding(suppressed="SEC-1")]) is Severity.INFO


def test_markdown_separates_active_from_suppressed():
    rendered = to_markdown(
        [_finding(), _finding(severity=Severity.LOW, suppressed="SEC-1 (expires x)")],
        title="Report",
        context={"Organization": "test-org"},
    )
    assert "## HIGH (1)" in rendered
    assert "Suppressed by accepted exception" in rendered
    assert "SEC-1" in rendered
    assert "**Organization:** test-org" in rendered


def test_markdown_handles_a_clean_run():
    assert "No active findings." in to_markdown([], title="Report")


def test_json_output_is_machine_readable():
    payload = json.loads(to_json([_finding()], scan_type="iam-scan"))
    assert payload["scan_type"] == "iam-scan"
    assert payload["summary"]["HIGH"] == 1
    assert payload["findings"][0]["rule_id"] == "IAM002"


def _args(samples, root, command, *extra):
    return [
        command,
        "--config",
        str(root / "config" / "governance-policy.yaml"),
        *extra,
    ]


@pytest.fixture
def root(samples):
    return samples.parent


def test_iam_scan_cli_fails_on_critical(samples, root, capsys):
    code = main(
        _args(samples, root, "iam-scan", "--policy", str(samples / "iam-policy.json"))
    )
    out = capsys.readouterr()
    assert code == 1
    assert "IAM Least-Privilege Findings" in out.out
    assert "FAILED" in out.err


def test_fail_on_none_still_reports(samples, root, capsys):
    code = main(
        _args(
            samples,
            root,
            "iam-scan",
            "--policy",
            str(samples / "iam-policy.json"),
            "--fail-on",
            "none",
        )
    )
    assert code == 0
    assert "IAM001" in capsys.readouterr().out


def test_access_review_cli_writes_markdown_and_csv(samples, root, tmp_path, capsys):
    out = tmp_path / "review.md"
    csv_path = tmp_path / "review.csv"
    code = main(
        _args(
            samples,
            root,
            "access-review",
            "--policy",
            str(samples / "iam-policy.json"),
            "--roster",
            str(samples / "roster.csv"),
            "--out",
            str(out),
            "--csv",
            str(csv_path),
        )
    )
    capsys.readouterr()
    assert code == 1  # the sample contains a leaver who kept access
    assert "Review worklist" in out.read_text()
    assert csv_path.exists()


def test_privacy_scan_json_output(samples, root, tmp_path, capsys):
    out = tmp_path / "privacy.json"
    main(
        _args(
            samples,
            root,
            "privacy-scan",
            "--inventory",
            str(samples / "data-inventory.yaml"),
            "--format",
            "json",
            "--out",
            str(out),
            "--fail-on",
            "none",
        )
    )
    capsys.readouterr()
    payload = json.loads(out.read_text())
    assert payload["scan_type"] == "privacy-scan"
    assert payload["summary"]["CRITICAL"] >= 1


def test_ropa_cli_renders_a_table(samples, capsys):
    code = main(["ropa", "--inventory", str(samples / "data-inventory.yaml")])
    out = capsys.readouterr().out
    assert code == 0
    assert "Record of Processing Activities" in out
    assert "bq.payments.transactions" in out
