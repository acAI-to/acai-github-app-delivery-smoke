Closes #<issue-number>

Tier: governance/tier-<0|1|2>
Repository kind: <harness|apps|acai-ops>
Change class: <mechanical|routine|bugfix|governance|other>
Risk tags: <comma-separated tags or none>
GitHub status: <enforced|advisory/pre-enforcement|unknown>
Adversarial profile: <automated|focused|independent-review>
Action phase: <reviewable-artifact|live-mutation>
Merge effect: <none|live-mutation>

<!-- Linked Tier-1 child only: Parent issue: #<parent>; Parent rubric digest: <sha256>; No live mutation: true -->

## Approved plan

Copy the approved issue plan or link its exact section.

## Fixed rubric

| Criterion | Owner | Evidence |
|---|---|---|
| <criterion> | <manager|tester|independent-review> | <command, test, or artifact> |

## Tier-specific gates

- Tier 0: Gate A is required. Record the automated/mechanical adversarial scope; no director/operator approval or Gate B is claimed.
- Tier 1: record Gate A and the documented Gate-B waiver; no separate approval artifact is required.
- Tier 2: link the issue’s digest-bound independent-review artifact and the operator `acai-plan-approved` bot attestation. Gate B remains pending until the final full head SHA is independently reviewed.

## Gate A

Pending implementation validation.

## Gate B (Tier 2 only)

Post the following through the trusted independent-review relay after reviewing the final head. A new commit invalidates it.

```text
<!-- ACAI-GATE-B -->
Gate-B: PASS
Commit: <full 40-character head SHA>
Reviewer: independent-review
Session: <independent review session id>
```

## Outstanding gates

- Per-repo onboarding/protection, UAT, canary, rollout, or missing trusted-relay evidence.
