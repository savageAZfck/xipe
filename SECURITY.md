# Security

## Reporting

Open an issue at https://github.com/savageAZfck/xipe/issues or email the maintainer (see Cargo.toml authors). For vulnerabilities in the signing or verification path, prefer private contact before public disclosure.

## Scope

- Journal chain integrity, artifact-hash verification, transition enforcement, and signature correctness are in-scope security properties.
- The amendment directory is created `0700`; keep it owner-only.
- The trust boundary is documented in THREAT_MODEL.md — read it before relying on artifacts in adversarial settings.

## Verifying releases

Crate sources are auditable; crates.io metadata includes repository linkage. An artifact signed by a compromised key is forgeable — prefer hardware-bound `Signer` implementations and anchor the journal tip into an external ledger for high-assurance deployments.
