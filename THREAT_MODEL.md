# Threat model

xipe exists because the dangerous property of self-modifying systems is
not that they change — it is that they change *without a record the owner
can verify*. The crate defends the record, not the change.

## What it defends against

- **Silent self-modification.** Every mutation that touches
  behavior-bearing state must pass through the lifecycle; the journal
  proves what was proposed, who deliberated, who ratified, what was
  applied, and what it measured afterward. Anything applied outside the
  lifecycle fails `verify_artifact` — the journal-committed
  `artifact_sha256` no longer matches the file.
- **History forgery.** The journal is hash-chained per line
  (`prev_hash → entry_hash`). Rewriting or truncating history breaks the
  chain for `verify_journal`.
- **Quorum self-dealing.** Constitutional-tier surfaces (policy, quorum,
  gate changes) can never be ratified by the quorum — unanimous or not.
  The body that argues cannot grant itself authority.
- **Divided-council installation.** Statutory amendments auto-ratify only
  on unanimity. A 3–1 vote holds for the human, with the dissent recorded
  verbatim in the artifact.

## What it does not defend against

- **A malicious human ratifier.** If the owner ratifies a hostile
  amendment, the record will be honest about who did it. The crate makes
  decisions provable, not wise.
- **Filesystem-level destruction.** An attacker who can delete the whole
  directory deletes the evidence. Keep the journal replicated or anchored
  elsewhere (e.g., an append-only ledger) for high-assurance deployments.
- **Key compromise.** Artifact signatures prove "the key signed," not
  "the signer intended." Prefer hardware-bound signers (Secure Enclave,
  HSM) via the `Signer` trait when the threat model includes stolen keys.
- **The mutation itself.** xipe records the amendment; the caller performs
  it. A buggy or malicious mutation applied under a valid ratification is
  still a valid — and auditable, and revertible — amendment.

## Honest scope

The journal is tamper-evident, not tamper-proof: an attacker who rewrites
the file AND recomputes the chain produces a self-consistent forgery.
Defense against that is anchoring — periodically committing the journal
tip hash to an external store (a second ledger, a signed checkpoint, a
remote witness). That composition is deliberate and out of scope here.
