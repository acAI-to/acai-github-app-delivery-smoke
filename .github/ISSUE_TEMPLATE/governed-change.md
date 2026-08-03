---
name: Governed change
about: Bounded issue-first plan for an ACAI repository change
title: ""
labels: ""
---

## Tier + justification
Tier: governance/tier-<0|1|2>
Changed paths: <planned repo-relative paths or globs>
Justification: <why this declared tier meets the computed floor>

## Simplest viable approach
<State the simplest approach that meets the goal; justify or drop any added complexity.>
Simpler alternative considered: X, rejected because Y
Required tags: `destructive`/`data-loss` for data-deleting changes; `fleet-wide` for multi-host changes.

## Governance metadata
Repository kind: <harness|apps|acai-ops>
Change class: <mechanical|routine|bugfix|governance|other>
Risk tags: <comma-separated tags or none>
GitHub status: <enforced|advisory/pre-enforcement|unknown>
Adversarial profile: <automated|focused|luna-max>
Action phase: <reviewable-artifact|live-mutation>
Merge effect: <none|live-mutation>

<!-- Linked children additionally repeat Parent issue, Parent rubric digest, and No live mutation: true on both issue and PR. -->

## Goal
<!-- Keep the issue plan at or below 40 lines. -->

## Plan

## Fixed rubric
1. Criterion — validation owner — check/evidence

## Non-goals

## Tier-specific approval path
- Tier 0: issue, issue-linked branch/draft PR, and Gate A only.
- Tier 1: no separate approval artifact; Gate B is a documented waiver.
- Tier 2: digest-bound independent Luna/max plan-review artifact, then operator-only `acai-plan-approved` plus its bot attestation; final exact-head independent Luna/max Gate B is required.

For Tier 2, the independent Luna/max plan-review comment must contain `Repository`, `Issue`,
`Purpose: plan-review`, `Digest-SHA256`, `Reviewer`, `Session`, and
`Verdict: PASS`. Plan/task/evidence edits may be resolved by agents; edits to Goal, Fixed rubric, or Non-goals require a new approval path.
