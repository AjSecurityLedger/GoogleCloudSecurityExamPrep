# Access Governance & Privacy Engineering Toolkit

Checks that turn a Google Cloud IAM allow policy and a declared data inventory
into the artefacts an access-governance and privacy programme actually runs on:
least-privilege findings, a routed user access review campaign, privacy control
findings, and an Article 30 record of processing activities.

Written policy lives in [`docs/`](docs/); the machine-readable form of the same
rules lives in [`config/governance-policy.yaml`](config/governance-policy.yaml).
Changing a control means changing that file in a pull request, which is the
point — the programme is reviewable rather than remembered.

```
agp/       analysers, policy loader, reporting, CLI
config/    the governance policy: trusted domains, privileged roles, SoD, exceptions
docs/      the programme itself, the privacy engineering standard, control mapping
samples/   synthetic IAM policy, HR roster and data inventory (no real identities)
tests/     pytest suite covering every rule and both output formats
```

## Quick start

```bash
cd access-governance
pip install -e ".[dev]"     # or: pip install pyyaml pytest
make all                    # runs every scan against samples/, writes to out/
```

Against real data:

```bash
gcloud projects get-iam-policy ajsl-prod-payments --format=json > policy.json

python -m agp iam-scan       --policy policy.json --config config/governance-policy.yaml
python -m agp access-review  --policy policy.json --roster roster.csv --csv campaign.csv
python -m agp privacy-scan   --inventory data-inventory.yaml
python -m agp ropa           --inventory data-inventory.yaml --out out/ropa.md
```

Each command takes `--format md|json`, `--out PATH`, and `--fail-on
critical|high|medium|low|none`. `--fail-on` sets the exit code, so the same
command that produces the auditor's report gates a pipeline.

## What each command does

**`iam-scan`** — flattens allow policies into one row per principal and applies
the least-privilege rules: public exposure, primitive roles, external
identities, standing privilege with no time bound, over-powered service
accounts, bindings left behind by deleted identities, segregation-of-duties
conflicts, and direct user bindings that bypass group-based provisioning.
Accepted exceptions suppress a finding only while they are unexpired — an
exception with no end date is treated as expired by design.

**`access-review`** — builds a quarterly UAR campaign: each entitlement is
routed to the principal's manager (from the HR roster) or the recorded owner of
the service account or group, and emitted as a reviewer worklist in Markdown and
CSV. Anything that should never have reached review time — a leaver who kept
access, an identity absent from HR, a contractor holding privilege, a public
binding nobody can attest to — is separated out as a joiner/mover/leaver
automation failure.

**`privacy-scan`** — checks the declared data inventory for encryption of
restricted data, retention breaches against the declared period, missing purpose
or legal basis, residency and transfer safeguards, DSAR reachability, sensitive
data scan freshness, ownership, and broad access to personal data.

**`ropa`** — renders the Article 30 record of processing from the same inventory
the checks run against, so the document handed to a regulator and the state of
the estate cannot drift apart.

## Rules

Access governance: `IAM001` public exposure · `IAM002` primitive role ·
`IAM003` external identity · `IAM004` standing privilege · `IAM005` privileged
service account · `IAM006` deleted principal · `IAM007` SoD conflict ·
`IAM008` direct user binding · `IAM009` expired condition · `UAR001` orphan ·
`UAR002` leaver · `UAR003` unowned entitlement · `UAR004` unattestable public
binding · `UAR005` contractor privilege.

Privacy: `PRV001` restricted data without CMEK · `PRV002` retention breach ·
`PRV003` retention undeclared or excessive · `PRV004` no purpose or legal basis ·
`PRV005` residency violation · `PRV006` DSAR unreachable · `PRV007` stale
sensitive-data scan · `PRV008` no owner · `PRV009` unsafeguarded transfer ·
`PRV010` broad access to personal data.

Each rule maps to a framework control and a Google Cloud fix in
[`docs/control-mapping.md`](docs/control-mapping.md).

## Input formats

- **IAM policy** — exactly what `gcloud ... get-iam-policy --format=json`
  returns, either a single policy or a bundle:
  `{"resources": [{"name": "projects/x", "policy": {...}}]}`.
- **Roster CSV** — `email,name,department,manager_email,status,employment_type`.
  `status` of anything other than `active` is treated as a leaver.
- **Data inventory YAML** — see [`samples/data-inventory.yaml`](samples/data-inventory.yaml);
  unknown fields are rejected rather than silently ignored, so a typo in a
  retention field fails loudly instead of disabling a control.

## Continuous enforcement

[`.github/workflows/access-governance.yml`](../.github/workflows/access-governance.yml)
runs the test suite and every scan against the samples on each change. Point the
scan steps at exported policies from a read-only service account (Workload
Identity Federation, no keys) to gate real estates.

## Tests

```bash
python -m pytest
```

Time-sensitive assertions are pinned to a fixed instant so expiry and staleness
rules stay deterministic.
