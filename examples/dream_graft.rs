//! Worked example: a nightly self-improvement pass that proposes a weight
//! graft, sends it to a quorum, and adopts it only through the amendment
//! lifecycle — the exact shape of Bad Apple's dream loop.

use serde_json::json;
use xipe::{Constitution, Status, Verdict, Vote};

// Your quorum — a council of models, a rules engine, a human queue.
// Here: four seats all approve.
fn deliberate(_surface: &str, _evidence: &serde_json::Value) -> Verdict {
    Verdict::from_votes(
        vec!["seat-a", "seat-b", "seat-c", "seat-d"]
            .into_iter()
            .map(|seat| Vote {
                seat: seat.into(),
                vote: "approve".into(),
                rationale: "eval improved".into(),
            })
            .collect(),
        "approve",
        "4/4 approve",
    )
}

fn main() -> xipe::Result<()> {
    let dir = std::env::temp_dir().join("xipe-example");
    let con = Constitution::builder(&dir)
        // The rules that bind the quorum itself never self-ratify.
        .constitutional(&["policy_patch", "quorum_change"])
        .build()?;

    // 1. The improvement pass proposes itself — evidence is committed.
    let id = con.propose(
        "weight_graft",
        json!({
            "candidate_sha256": "9f2a…",
            "prev_adapter_sha256": "3c11…",
            "train_rows": 412,
            "val_loss": "0.91 → 0.84",
        }),
        "dream",
    )?;

    // 2. Deliberation. Statutory + unanimous → auto-ratified; anything
    //    contested holds for the human.
    let amendment = con.load(&id).unwrap();
    let verdict = deliberate(&amendment.surface, &amendment.evidence);
    match con.record_verdict(&id, &verdict)? {
        Status::Ratified => {
            // 3. The caller performs the actual mutation, then proves it.
            let new_sha = "9f2a…"; // graft_weights() in the real system
            con.mark_applied(
                &id,
                json!({
                    "adapter_sha256": new_sha,
                    "revert_ref": "lora_adapters/dream-prev",
                }),
            )?;
            con.mark_measured(
                &id,
                json!({
                    "val_loss_baseline": 0.91,
                    "val_loss_final": 0.84,
                }),
            )?;
        }
        Status::Held => println!("held for human: `xipe ratify {id}`"),
        _ => {}
    }

    // 4. Prove the whole record — journal chain + every artifact hash.
    con.verify_all()?;
    println!("lifecycle complete; {id} fully on record");
    Ok(())
}
