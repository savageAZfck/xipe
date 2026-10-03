# xipe spec — v0.1

The amendment lifecycle protocol. Any implementation producing conforming
artifacts and journal entries interoperates with this crate's verifier.

## Amendment artifact

One canonical JSON file per amendment at `<dir>/<id>.json`:

```json
{
  "kind": "xipe.amendment",
  "version": 1,
  "id": "amend-<UTC-stamp>-<6hex>",
  "surface": "<what is being changed>",
  "tier": "statutory | constitutional",
  "status": "proposed | ratified | held | applied | reverted | rejected",
  "proposed_at": "<RFC3339>",
  "proposed_by": "<actor>",
  "evidence": { ... },
  "council": { "decision", "mean", "dissent", "unanimous_approve",
               "summary", "votes": [{seat, vote, rationale}] },
  "ratified_by": "quorum-unanimous | human",
  "ratified_at": "<RFC3339>",
  "applied_at": "<RFC3339>", "post_state": { ... },
  "measured": { ... }, "measured_at": "<RFC3339>",
  "rejected_by": "human", "rejected_at": "<RFC3339>",
  "reverted_at": "<RFC3339>",
  "signature": { "scheme", "pubkey", "sig" }, "signed": true
}
```

Unknown fields MUST be preserved on read (the `extra` bag) so forward-
compatible artifacts round-trip.

## Lifecycle transitions

| From | Via | To |
|---|---|---|
| — | `propose` | `proposed` |
| `proposed` | `record_verdict`, statutory + `unanimous_approve` | `ratified` (signed) |
| `proposed` | `record_verdict`, constitutional OR divided | `held` |
| `held` / `proposed` | `ratify` (human) | `ratified` (signed) |
| `held` / `proposed` | `reject` (human) | `rejected` (terminal) |
| `ratified` | `mark_applied` | `applied` |
| `applied` | `mark_measured` | `applied` (+ `measured`) |
| `applied` | `mark_reverted` | `reverted` (terminal) |

Every other transition is an `IllegalTransition` error. `rejected` and
`reverted` are terminal; nothing leaves them.

## Journal

`amendments.jsonl`, one canonical JSON line per transition:

```json
{"ts":"<RFC3339>","amendment_id":"...","transition":"...",
 "artifact_sha256":"<sha256 of canonical artifact at this transition>",
 "prev_hash":"<entry_hash of previous line | \"genesis\">",
 "entry_hash":"<sha256 of this line sans entry_hash>"}
```

Canonicalization: lexicographically sorted object keys at every depth,
compact separators, UTF-8. Verification recomputes every `entry_hash`,
checks every `prev_hash` link, and (with `verify_all`) re-hashes every
artifact against its last committed `artifact_sha256`.

## Verdict ingestion

The lifecycle keys on one field: `unanimous_approve`. Deliberation bodies
are external; `Verdict::from_votes` computes the derived fields
(`mean` = approval fraction, `dissent` = 1 − mean, empty quorum is never
unanimous).
