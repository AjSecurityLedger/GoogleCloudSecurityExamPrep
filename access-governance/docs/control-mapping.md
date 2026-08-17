# Rule → control → Google Cloud mapping

Every rule the toolkit implements, the framework control it evidences, and the
Google Cloud mechanism that actually fixes it. Use this table when an auditor
asks "how do you know?" and when studying for the Professional Cloud Security
Engineer exam — the exam's domains are the columns.

## Access governance rules

| Rule | Finding | Framework | Fix in Google Cloud |
| --- | --- | --- | --- |
| `IAM001` | `allUsers` / `allAuthenticatedUsers` binding | CIS-GCP, NIST AC-3, ISO 27001 A.5.15 | Remove binding; `constraints/iam.allowedPolicyMemberDomains`; uniform bucket-level access |
| `IAM002` | Primitive role (`owner`/`editor`) granted | NIST AC-6, SOC 2 CC6.1 | Predefined or custom roles built from IAM Recommender usage data |
| `IAM003` | External identity holds access | NIST AC-2(1), SOC 2 CC6.2 | Dedicated third-party project, conditional time-bound grant, domain restriction |
| `IAM004` | Standing privileged grant, no time bound | NIST AC-2(11), SOC 2 CC6.3 | Privileged Access Manager, or `request.time` IAM condition |
| `IAM005` | Service account holds privileged role | NIST AC-6, SOC 2 CC6.1 | One SA per workload; Workload Identity Federation; restrict `serviceAccountTokenCreator` |
| `IAM006` | Binding references a deleted principal | NIST AC-2(3) | Remove stale bindings in leaver processing |
| `IAM007` | Segregation of duties conflict | NIST AC-5, ISO 27001 A.5.3 | Split duties; compensating detective control with alerting |
| `IAM008` | Direct user binding instead of a group | NIST AC-2 | Cloud Identity group membership as the single control point |
| `IAM009` | Expired conditional binding left in place | NIST AC-2(3) | Delete on expiry; treat as cleanup debt, not access |
| `UAR001` | Entitlement for an identity absent from HR | NIST AC-2(j) | Reconcile with the authoritative identity source; revoke |
| `UAR002` | Leaver retains access | NIST AC-2(3), ISO 27001 A.5.18 | Fix leaver automation; measure time-to-revoke |
| `UAR003` | Entitlement with no accountable reviewer | SOC 2 CC6.2 | Record an owner for every service account and group |
| `UAR004` | Public binding cannot be attested | NIST AC-3 | Remove before the campaign opens |
| `UAR005` | Contractor holds a privileged role | NIST AC-2(1) | Time-box to the engagement; internal sponsor re-approves each cycle |

## Privacy rules

| Rule | Finding | Framework | Fix in Google Cloud |
| --- | --- | --- | --- |
| `PRV001` | Restricted data without CMEK | GDPR Art. 32, NIST SC-28 | Cloud KMS CMEK with rotation; `constraints/gcp.restrictNonCmekServices` |
| `PRV002` | Data held past its declared retention | GDPR Art. 5(1)(e) | BigQuery table/partition expiration; GCS lifecycle rules |
| `PRV003` | No retention period, or above the ceiling | GDPR Art. 5(1)(e), ISO 27701 A.7.4.7 | Declare per purpose and automate enforcement |
| `PRV004` | No purpose or legal basis recorded | GDPR Art. 6, Art. 30 | Complete the RoPA entry with the business owner |
| `PRV005` | Personal data outside approved regions | GDPR Ch. V | `constraints/gcp.resourceLocations` at folder level |
| `PRV006` | No subject key: DSAR cannot be fulfilled | GDPR Art. 15–17 | Add a stable subject identifier or documented join path |
| `PRV007` | Sensitive-data scan missing or stale | GDPR Art. 30, NIST RA-2 | Recurring Sensitive Data Protection discovery + inspection jobs |
| `PRV008` | Data asset with no owner | ISO 27701 A.7.2 | Assign a named data owner |
| `PRV009` | Transfer without an approved safeguard | GDPR Ch. V | Record SCCs / adequacy / BCRs plus the transfer impact assessment |
| `PRV010` | Broad or external access to personal data | GDPR Art. 32, NIST AC-3 | Revoke; verify processor agreement; check access logs |

## Exam domain cross-reference

| PCSE domain | Where it shows up here |
| --- | --- |
| Configuring access within a cloud solution | `IAM001`–`IAM009`, role model in the programme doc |
| Configuring network security | VPC Service Controls perimeters around restricted-tier data |
| Ensuring data protection | `PRV001`–`PRV010`, CMEK, Sensitive Data Protection, de-identification |
| Managing operations | Access review cycle, log sinks, alerting, CI gating |
| Ensuring compliance | RoPA generation, exception register, control mapping in this file |
