# xipe

Constitutional self-modification for autonomous systems.

Named for **Xipe Totec**, who shed his own skin as sacred rite — renewal by
ritual, not by force. This crate embodies that theology: a system may change
its own behavior-bearing state, but only through a process that leaves a
signed, verifiable record.

Every change to a system's own state — weight grafts, strategy updates,
prompt patches, policy changes — is an **amendment**:

```
proposed → deliberated → ratified | held → applied → measured → reverted?
                                  ↘ rejected
```

Each lifecycle transition is written to a hash-chained journal
(`amendments.jsonl`, `prev_hash → entry_hash` per line) plus a canonical
JSON artifact per amendment. `verify_journal()` re-proves the whole chain —
tampering with history is detectable, not merely absent.

## Two tiers

| Tier | Surfaces | Ratification |
|---|---|---|
| `Statutory` | weight grafts, strategy updates, prompt patches | Unanimous quorum approval auto-ratifies and signs; anything divided holds for the human |
| `Constitutional` | policy changes, quorum changes, gate changes | **Human ratification only, always.** The quorum can argue; it cannot amend the rules that bind it |

## Usage

```rust
use xipe::{Constitution, Tier, Status, Verdict, Signer, Signature};
use serde_json::json;

let con = Constitution::builder("/var/lib/myagent/amendments")
    .constitutional(&["policy_patch", "quorum_change"])
    .signer(Box::new(my_signer))      // optional: Secure Enclave, Ed25519, HSM
    .sink(Box::new(my_event_sink))    // optional: audit ledger, flight tape
    .build()?;

// A nightly self-improvement pass proposes a weight graft:
let id = con.propose("weight_graft", json!({
    "candidate_sha256": "...",
    "val_loss": "0.91 → 0.84",
}), "dream")?;

// The quorum deliberates. Unanimity on a statutory surface auto-ratifies;
// a contested verdict holds for the human (`con.ratify(&id)`).
match con.record_verdict(&id, &council_verdict)? {
    Status::Ratified => {
        apply_the_mutation()?;                        // caller's mutation
        con.mark_applied(&id, json!({"post_sha256": "..."}))?;
        con.mark_measured(&id, json!({"eval_delta": -0.02}))?;
    }
    Status::Held => { /* human decision pending */ }
    _ => {}
}

con.verify_journal()?;  // end-to-end chain proof
```

## What this crate does and does not do

It **does**: own the amendment artifact + journal, enforce tier rules and
legal transitions, sign artifacts at ratification, verify the chain.

It does **not**: perform the mutation itself, supply the quorum, or supply
the signer. Those are traits/seams — `Signer`, `EventSink`, and your
verdict source — so the same constitution governs any surface and any
deliberation body.

Extracted from the amendment layer of
[Bad Apple](https://github.com/savageAZfck/Bad_Apple), where it governs
nightly self-modification of a live AGI organism. Spec'd organs:
[touchstone](https://github.com/savageAZfck/touchstone).

## License

MIT
