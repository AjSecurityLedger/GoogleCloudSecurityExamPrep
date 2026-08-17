# Access Governance Programme — Google Cloud

The programme this repository automates. The code in `agp/` enforces what is
written here; the policy file `config/governance-policy.yaml` is the executable
form of it. If a rule exists in one and not the others, that gap is the finding.

## 1. Principles

1. **Access is granted to a role, never to a person.** People inherit access
   through Cloud Identity groups, so joiner/mover/leaver automation has exactly
   one control point.
2. **Standing privilege is the exception.** Roles that can change security
   posture, read protected data, or alter the audit trail are issued
   just-in-time or carry an expiring IAM condition.
3. **Every entitlement has an accountable human.** Service accounts and groups
   included. An entitlement nobody owns cannot be attested to, so it gets
   revoked rather than renewed.
4. **Exceptions are time-boxed and ticketed.** An exception with no end date is
   an undocumented policy change; the tooling treats it as expired.
5. **The evidence is generated, not assembled.** Reports are produced from live
   policy data on a schedule, so audit season is a re-run rather than a project.

## 2. Role model

| Layer | What lives here | Google Cloud construct |
| --- | --- | --- |
| Organisation | Guardrails that no project can opt out of | Org policy constraints, org-level IAM |
| Folder (env) | Environment-wide separation: prod, non-prod, sandbox | Folder IAM, VPC Service Controls perimeters |
| Project | Workload access, granted to groups | Project IAM bindings with conditions |
| Resource | Data-level exceptions only | Bucket / dataset / secret IAM |

Role design rules:

- **No primitive roles.** `roles/owner` and `roles/editor` are unscopable and
  span every API. Replace with predefined roles, or a custom role derived from
  90 days of observed usage (IAM Recommender, Policy Analyzer).
- **Custom roles are versioned in code**, named `ajsl.<domain>.<function>`, and
  reviewed like any other change.
- **Break-glass accounts** are separately named, MFA-enforced with a hardware
  key, alert on every authentication, and are expected to hold broad roles —
  what is reviewed is that use was short, justified, and rare.

## 3. Guardrails to enforce first

| Guardrail | Constraint | Stops |
| --- | --- | --- |
| Domain restricted sharing | `constraints/iam.allowedPolicyMemberDomains` | `allUsers`, `allAuthenticatedUsers`, external identities |
| No service account keys | `constraints/iam.disableServiceAccountKeyCreation` | Long-lived credentials that leak into repos |
| Resource locations | `constraints/gcp.resourceLocations` | Personal data landing outside approved regions |
| CMEK required | `constraints/gcp.restrictNonCmekServices` | Restricted data on keys you cannot revoke |
| Uniform bucket access | `constraints/storage.uniformBucketLevelAccess` | ACLs that bypass IAM review entirely |
| Public IP / external sharing | `constraints/compute.vmExternalIpAccess` | Unreviewed internet exposure |

Guardrails are preventive and cost nothing to keep. Detection (below) exists for
what they cannot catch.

## 4. Joiner / mover / leaver

| Event | SLA | Control | Detection when it fails |
| --- | --- | --- | --- |
| Joiner | Access active on day 1, baseline only | HR system → Cloud Identity provisioning → group membership | `UAR001` orphaned entitlement |
| Mover | Old access removed within 5 working days | Group membership recalculated from the HR attribute, not added to | Drift between roster department and group membership |
| Leaver | Revoked within 4 hours of termination | HR status change suspends the account and strips group membership | `UAR002` leaver retains access |
| Third party | Access ends with the engagement date | Time-bound IAM conditions, dedicated project | `UAR005` contractor privilege, `IAM003` external identity |

The leaver SLA is the programme's headline metric: **time from termination to
last access revoked**, measured per event rather than averaged.

## 5. Access review (UAR) cycle

Quarterly, driven by `agp access-review`:

1. **Collect** — export allow policies for every project, folder and the
   organisation (`gcloud projects get-iam-policy ... --format=json`).
2. **Route** — each entitlement goes to the principal's manager (from the HR
   roster) or the recorded owner for a service account or group.
3. **Decide** — reviewers mark `APPROVE`, `REVOKE`, or `MODIFY`. No decision by
   the due date defaults to `REVOKE`.
4. **Revoke** — decisions are applied through the same infrastructure-as-code
   path that grants access, never by hand in the console.
5. **Evidence** — the campaign CSV, the generated Markdown, and the resulting
   commits form the audit package.

Anything raised in the campaign's *exceptions* section is not review material —
it is an automation failure that should have been caught before the campaign
opened.

## 6. Separation of duties

Enforced by `IAM007`. The conflicts that matter most in Google Cloud:

| Conflict | Why it matters |
| --- | --- |
| KMS admin + data reader | One principal can decrypt protected data unilaterally |
| IAM admin + logging admin | Whoever grants access can erase the record of granting it |
| Secret admin + token creator | Mint a workload credential, then read what it protects |
| Billing admin + compute admin | Create spend and approve it with no second party |

Where the org is too small to split a duty, the compensating control is
detective: alert on the action, review it out-of-band, and record the accepted
risk as a dated exception.

## 7. Detection

Preventive controls fail quietly; these are the signals that say so.

- **Log sink to a separate project** with restricted access — admin activity
  logs, data access logs on data stores, and the policy denied logs.
- **Alerts:** break-glass authentication; `SetIamPolicy` adding `allUsers` or
  `allAuthenticatedUsers`; service account key creation; org policy change;
  role grant outside the IaC pipeline's identity.
- **Recurring scans:** this toolkit in CI (see the workflow at
  `.github/workflows/access-governance.yml`), plus Security Command Centre and
  IAM Recommender for excess-permission signals.

## 8. Metrics that show the programme works

| Metric | Target |
| --- | --- |
| Time from termination to access revoked | < 4 hours, 100% of events |
| Primitive role bindings on production projects | 0 |
| Standing privileged grants without a time bound | 0 |
| Entitlements with no accountable owner | 0 |
| Review decisions completed by the due date | > 95% |
| Open exceptions past their end date | 0 |

## 9. Running the checks

```bash
gcloud projects get-iam-policy ajsl-prod-payments --format=json > policy.json
python -m agp iam-scan --policy policy.json --config config/governance-policy.yaml
python -m agp access-review --policy policy.json --roster roster.csv --csv campaign.csv
```

`--fail-on high` makes either command a merge gate; `--format json` feeds a
dashboard or SIEM.
