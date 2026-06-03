# Retention Log Privacy Scans

Public-safe source contracts and checker inputs for FEAT-164, the recurring retention/log privacy
scan hardening package that proposes `RDY-DIM-008 8 -> 9`.

This repository is intentionally narrow. It publishes schemas, sanitized fixtures, rule catalogs,
result codes, public checker inputs, package manifests, hash references, and reviewer-readable
summaries for recurring privacy scan validation. It does not publish raw logs, traces, support
exports, diagnostics bundles, private scanner findings, or restricted reviewer evidence.

## Repository Role

- Feature: `FEAT-164`
- Parent readiness blocker: `RDY-BLOCK-INTERNAL_AUDIT_95_DIM008-001`
- Target dimension: `RDY-DIM-008`
- Score movement: proposal-only `8 -> 9`
- Default branch: `main`

FEAT-137 remains the accepted one-time no-durable-join proof baseline. FEAT-164 must prove a new
scan run, scanner baseline identity, output-family coverage, observability/support-export drift
checks, and public/private boundary validation. Restating FEAT-137 as recurring proof is a blocking
validation failure.

## Layout

```text
schemas/
  retention-log-privacy-recurring-scan-source.schema.json
  retention-log-privacy-recurring-scan-package-manifest.schema.json
rules/
  forbidden-material-catalog.json
  output-family-registry.json
examples/
  release-baseline/
    retention-log-privacy-recurring-scan-source.json
  negative/
    retention-log-privacy-recurring-scan-negative-fixtures.json
  result-codes.json
packages/
  retention-log-privacy-recurring-scan/<scan-run-id>/
    retention-log-privacy-recurring-scan-package.json
    retention-log-privacy-recurring-scan-manifest.json
```

Generated packages are expected under
`packages/retention-log-privacy-recurring-scan/<scan-run-id>/` after the promoter/checker is
implemented. Until then, the schema files define the public contract surface.

## Public Boundary

Allowed public material:

- Stable ids, branch names, commit hashes, manifest hashes, artifact hashes, and generated-at times.
- Sanitized source fixtures, rule catalogs, output-family registries, and expected result codes.
- Public-safe summaries, package manifests, no-payload restricted evidence refs, and non-claim
  wording.
- Negative fixtures that use redacted placeholders rather than real restricted material.

Restricted material that must not be committed here:

- Secrets, credentials, tokens, private keys, or signing material.
- Raw logs, raw traces, metrics payloads, diagnostics bundles, support export payloads, support case
  details, or private scanner findings.
- Customer, voter, shareholder, trustee, operator, account, or support-case identifiers.
- Ballot choices, receipt capabilities, vote secrets, witnesses, private randomness, or
  accepted-to-published mappings.
- Private HushDocuments paths, restricted reviewer indexes, legal/customer material, vulnerability
  details, exploit material, provider details, or local workstation paths.

When restricted evidence is needed, public artifacts may reference only an opaque restricted
evidence id, expected hash, visibility marker, and no-payload note. The restricted payload itself
must remain in the approved private reviewer location.

## Validation Contract

The checker must fail closed when:

- FEAT-137 proof package refs are missing, stale, mismatched, superseded, blocked, or unknown.
- Scanner baseline, forbidden-material catalog, or output-family registry refs are missing or not
  hash-bound.
- Logs, traces, metrics, support exports, packages, reports, CI outputs, or restricted indexes
  appear without an explicit scanner decision.
- Public outputs contain restricted privacy material.
- Public-only validation depends on private repositories, private paths, credentials, or live
  private services.
- The package claims direct readiness-register mutation or proposes any score movement other than
  proposal-only `RDY-DIM-008 8 -> 9`.

## Non-Claims

This repository does not certify privacy compliance, legal sufficiency, public/state election
readiness, independent audit acceptance, or final readiness-register mutation. It only provides
public-safe inputs and outputs for deterministic validation of the FEAT-164 evidence package.
