# Privacy Engineering — Google Cloud

Privacy fails as an engineering problem long before it fails as a legal one: a
retention promise nobody automated, a deletion request that cannot reach a
table, a dataset copied to a region the notice never mentioned. This document
is the engineering half, and `agp privacy-scan` enforces it.

## 1. The inventory is the control surface

Everything downstream — retention, residency, encryption, data subject rights —
depends on knowing where personal data rests. An asset absent from
`samples/data-inventory.yaml` is an asset nobody can make promises about.

| Field | Why it exists |
| --- | --- |
| `data_categories` | Drives the handling tier; dotted taxonomy so rules match a prefix (`pii.national_id` inherits `pii`) |
| `purpose`, `legal_basis` | Article 30 record; without them the processing cannot be justified |
| `retention_days` / `oldest_record_days` | Declared policy vs. observed reality — the gap is the finding |
| `subject_key` | The join path a DSAR uses; no key means rights cannot be fulfilled |
| `location`, `transfers`, `transfer_safeguard` | Residency and Chapter V transfer basis |
| `encryption` | CMEK vs. Google-managed: whether key access can be revoked and audited |
| `last_dlp_scan` | Whether the declared categories are verified or merely asserted |
| `access_principals` | Who can reach the data — reconciled against the IAM scan |

Keep the inventory honest with **Sensitive Data Protection (Cloud DLP)**
discovery and inspection jobs: profile BigQuery and Cloud Storage continuously,
and treat any *found* category that is not *declared* as a finding against the
asset owner.

## 2. Data classification tiers

| Tier | Examples | Minimum handling |
| --- | --- | --- |
| **Restricted** | National ID, health, payment card, special-category data | CMEK with rotation and split key admin; VPC-SC perimeter; data access logs on; access via approved group only, time-bound |
| **Confidential** | Contact details, account records, device identifiers | Google-managed keys acceptable; group-based access; retention declared and automated |
| **Internal** | Aggregates, pseudonymised analytics | Standard project controls |
| **Public** | Published content | No personal data by definition |

## 3. Privacy by design in the build path

- **Collect less.** The cheapest DSAR is the one about data you never stored.
  Challenge each new field at design review against a stated purpose.
- **Separate identifiers from behaviour.** Keep the mapping from `user_id` to
  identity in one governed store; downstream analytics gets the pseudonym.
- **De-identify in the pipeline, not the warehouse.** Cloud DLP transforms
  (masking, bucketing, format-preserving tokenisation with KMS-wrapped keys)
  applied before landing means the raw value never reaches analytics.
- **Make deletion a first-class path.** Design the erase path when you design
  the write path: table expirations, GCS lifecycle rules, and a documented
  cascade for derived copies, exports and backups.
- **Assume copies exist.** Every export, sandbox extract and notebook download
  is a new asset; if it is not in the inventory, it is invisible retention.

## 4. Data subject requests (DSAR) runbook

**SLA: one calendar month from receipt (extendable by two for complexity).**

1. **Intake and verify** the requester's identity, proportionately to the
   sensitivity of the data — verification must not become extra collection.
2. **Resolve identifiers**: map the requester to every `subject_key` in the
   inventory (account id, subscriber id, ticket email).
3. **Fan out** across assets that hold a matching key. Any asset with an empty
   `subject_key` (`PRV006`) is a gap — fix the asset, not the request.
4. **Assemble** access requests into a portable export; for erasure, run the
   deletion path and record what was suppressed instead of deleted (legal hold,
   statutory retention) and why.
5. **Propagate** to processors and derived stores — search indexes, caches,
   backups (record the backup expiry as the effective deletion date).
6. **Respond and log**: what was found, what was done, what was withheld and on
   what basis. The log is the evidence the SLA was met.

Engineering target: every asset holding personal data is reachable by an
automated fan-out. Manual archaeology per request means the design is wrong.

## 5. Retention

Declared retention that nothing enforces is a story, not a control.

| Store | Enforcement |
| --- | --- |
| BigQuery | Table/partition expiration set at creation; partition on the event date so expiry follows the record |
| Cloud Storage | Lifecycle rules; object retention lock only where a legal hold requires immutability |
| Cloud SQL | Scheduled deletion job with row counts emitted as metrics |
| Pub/Sub | Message retention bounded; no topic as an accidental archive |
| Logs | Bucket retention per log type; data access logs retained to the audit standard, not indefinitely |

`PRV002` compares the oldest record against the declared period — the check
that catches a deletion job which has been silently failing for months.

## 6. Residency and transfers

- Pin location with `constraints/gcp.resourceLocations` at the folder level so
  a new bucket cannot be created in the wrong region.
- Record every transfer with its mechanism (adequacy decision, SCCs, BCRs) and
  the transfer impact assessment. `PRV009` fails an unrecorded transfer.
- Remember that access is transfer: a support team in another jurisdiction
  reading EU data is a transfer even if the bytes never move.

## 7. DPIA trigger checklist

Run a DPIA before shipping when the change involves any of: large-scale
processing of special-category data; systematic monitoring of a public space or
of users; automated decisions with legal or similarly significant effects;
combining datasets collected for different purposes; new use of data collected
for something else; children's data; or a new international transfer.

The output that matters is engineering work: the mitigations become tickets,
and the residual risk is signed off by a named person with a review date.

## 8. Running the checks

```bash
python -m agp privacy-scan --inventory samples/data-inventory.yaml \
    --config config/governance-policy.yaml --fail-on high
python -m agp ropa --inventory samples/data-inventory.yaml --out out/ropa.md
```

The RoPA is generated from the same inventory the checks run against, so the
document handed to a regulator and the state of the estate cannot drift apart.
