# AJ Security Ledger — Google Cloud Security

Practical work behind the Google Cloud Professional Cloud Security Engineer
material: controls written down, then implemented as code that runs against real
policy exports rather than staying as notes.

## Projects

### [`access-governance/`](access-governance/) — Access Governance & Privacy Engineering Toolkit

Turns a Google Cloud IAM allow policy and a declared data inventory into the
artefacts a governance programme runs on:

- **`iam-scan`** — least-privilege findings: public exposure, primitive roles,
  external identities, standing privilege with no time bound, over-powered
  service accounts, stale bindings, segregation-of-duties conflicts.
- **`access-review`** — a quarterly user access review campaign, routed to each
  principal's manager or the recorded owner, with joiner/mover/leaver failures
  (leavers who kept access, orphaned identities, contractor privilege) separated
  out from ordinary review work.
- **`privacy-scan`** — encryption of restricted data, retention breaches against
  the declared period, purpose and legal basis, residency and transfer
  safeguards, DSAR reachability, sensitive-data scan freshness.
- **`ropa`** — an Article 30 record of processing generated from the same
  inventory the checks run against.

Controls live in one reviewable file
([`config/governance-policy.yaml`](access-governance/config/governance-policy.yaml)),
the programme they encode is written up in
[`docs/`](access-governance/docs/), and every rule maps to a framework control
and a Google Cloud fix in
[`docs/control-mapping.md`](access-governance/docs/control-mapping.md).

```bash
cd access-governance
pip install -e ".[dev]"
make all        # every scan against the synthetic samples, reports into out/
```

## Repository layout

```
access-governance/    the toolkit, its policy, docs, samples and tests
.github/workflows/    CI: tests plus the scans on every change
```

All sample identities, projects and data assets are synthetic.

## Licence

[MIT](LICENSE)
