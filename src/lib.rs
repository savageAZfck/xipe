//! xipe — constitutional self-modification.
//!
//! Every change to a system's own behavior-bearing state — weight grafts,
//! strategy updates, prompt patches, policy changes — is an *amendment*:
//! proposed as a signed artifact, deliberated by an external quorum,
//! ratified per its tier, applied, measured, and anchored into a
//! hash-chained journal. The crate records and proves the lifecycle; the
//! caller performs the actual mutation.
//!
//! Two tiers:
//! * [`Tier::Statutory`] — a unanimous approving quorum auto-ratifies;
//!   anything contested or merely-not-unanimous holds for the human.
//! * [`Tier::Constitutional`] — human ratification only, always. The quorum
//!   can argue; it cannot amend the rules that bind it.
//!
//! The point: self-modification is legal when it leaves a signed,
//! verifiable record — and structurally visible otherwise.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;

/// Amendment class. Determines who may ratify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Quorum unanimity may auto-ratify.
    Statutory,
    /// Human ratification only — the rules that bind the quorum itself.
    Constitutional,
}

/// Lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Proposed,
    Ratified,
    Held,
    Applied,
    Reverted,
    Rejected,
}

/// One seat's ballot in a deliberation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub seat: String,
    pub vote: String,
    #[serde(default)]
    pub rationale: String,
}

/// A quorum's deliberation outcome. `unanimous_approve` is the only field the
/// lifecycle keys on; the rest are recorded verbatim into the artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub decision: String,
    #[serde(default)]
    pub mean: f64,
    #[serde(default)]
    pub dissent: f64,
    pub unanimous_approve: bool,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub votes: Vec<Vote>,
}

impl Verdict {
    /// Build a verdict from raw ballots. `approve_value` is the ballot string
    /// counted as approval (e.g. `"approve"`, `"yes"`). `mean` is the approval
    /// fraction, `dissent` the non-approval fraction, `decision` `"approve"`
    /// iff every ballot approved. An empty ballot list is not unanimous.
    pub fn from_votes(votes: Vec<Vote>, approve_value: &str, summary: impl Into<String>) -> Self {
        let total = votes.len();
        let approvals = votes.iter().filter(|v| v.vote == approve_value).count();
        let mean = if total == 0 {
            0.0
        } else {
            approvals as f64 / total as f64
        };
        Self {
            decision: if total > 0 && approvals == total {
                "approve"
            } else {
                "mixed"
            }
            .into(),
            mean,
            dissent: 1.0 - mean,
            unanimous_approve: total > 0 && approvals == total,
            summary: summary.into(),
            votes,
        }
    }
}

/// A signature produced over the canonical artifact at ratification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub scheme: String,
    #[serde(default)]
    pub pubkey: String,
    pub sig: String,
}

/// Something that can sign canonical artifact bytes at ratification.
/// Implementations: Secure Enclave agent, Ed25519 key, HSM, remote signer.
pub trait Signer: Send + Sync {
    fn sign(&self, canonical: &[u8]) -> Option<Signature>;
}

/// Software Ed25519 signer (feature `ed25519`). For hardware-backed keys
/// (Secure Enclave, TPM, HSM) implement [`Signer`] yourself — the trait is
/// deliberately small so any attestation path can plug in.
#[cfg(feature = "ed25519")]
pub struct Ed25519Signer {
    keypair: ed25519_dalek::SigningKey,
}

#[cfg(feature = "ed25519")]
impl Ed25519Signer {
    /// Generate a fresh keypair.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        Self::from_bytes(&secret)
    }

    /// Wrap an existing 32-byte secret.
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        Self {
            keypair: ed25519_dalek::SigningKey::from_bytes(secret),
        }
    }

    /// Hex-encoded public key.
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.keypair.verifying_key().to_bytes())
    }
}

#[cfg(feature = "ed25519")]
impl Signer for Ed25519Signer {
    fn sign(&self, canonical: &[u8]) -> Option<Signature> {
        use ed25519_dalek::Signer as _;
        let sig = self.keypair.sign(canonical);
        Some(Signature {
            scheme: "ed25519".into(),
            pubkey: self.pubkey_hex(),
            sig: hex::encode(sig.to_bytes()),
        })
    }
}

/// Optional sink for lifecycle events (audit ledger, flight tape, logs).
pub trait EventSink: Send + Sync {
    fn emit(&self, event_type: &str, data: Map<String, Value>);
}

/// The signed artifact — one file per amendment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Amendment {
    pub kind: String,
    pub version: u32,
    pub id: String,
    pub surface: String,
    pub tier: Tier,
    pub status: Status,
    pub proposed_at: String,
    pub proposed_by: String,
    #[serde(default)]
    pub evidence: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub council: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratified_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratified_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_state: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measured: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measured_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverted_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
    /// Any fields a future version or extension wrote that we don't know.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Serde(serde_json::Error),
    Missing(String),
    /// Attempted a transition the current status forbids.
    IllegalTransition {
        id: String,
        status: Status,
        attempted: &'static str,
    },
    /// The hash-chained journal failed verification.
    JournalCorrupt {
        line: usize,
        reason: String,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Serde(e) => write!(f, "json: {e}"),
            Error::Missing(id) => write!(f, "no amendment {id}"),
            Error::IllegalTransition {
                id,
                status,
                attempted,
            } => {
                write!(f, "amendment {id} is {status:?} — cannot {attempted}")
            }
            Error::JournalCorrupt { line, reason } => {
                write!(f, "journal corrupt at line {line}: {reason}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Canonical JSON: sorted keys at every depth (serde_json Map is ordered),
/// compact separators. Signatures and journal hashes commit to these bytes.
fn canonical(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("serde_json serialization is total")
}

fn iso_now() -> String {
    // Compact civil-from-days UTC formatting — no chrono dependency.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn fresh_id(now: &str) -> String {
    let stamp: String = now
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let entropy = format!("{nanos}-{}", std::process::id());
    let suffix = &sha256_hex(entropy.as_bytes())[..6];
    format!("amend-{stamp}-{suffix}")
}

/// The constitution: surface→tier registry, artifact store, journal,
/// optional signer and event sink.
pub struct Constitution {
    dir: PathBuf,
    journal_path: PathBuf,
    tiers: std::collections::HashMap<String, Tier>,
    default_tier: Tier,
    signer: Option<Box<dyn Signer>>,
    sink: Option<Box<dyn EventSink>>,
    lock: Mutex<()>,
}

pub struct Builder {
    dir: PathBuf,
    journal_path: Option<PathBuf>,
    tiers: std::collections::HashMap<String, Tier>,
    default_tier: Tier,
    signer: Option<Box<dyn Signer>>,
    sink: Option<Box<dyn EventSink>>,
}

impl Builder {
    /// Journal path (default `<dir>/amendments.jsonl`).
    pub fn journal_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.journal_path = Some(path.into());
        self
    }
    /// Register a surface at a tier. Unregistered surfaces get
    /// `default_tier` (Statutory).
    pub fn surface(mut self, name: &str, tier: Tier) -> Self {
        self.tiers.insert(name.to_string(), tier);
        self
    }
    pub fn constitutional(mut self, names: &[&str]) -> Self {
        for n in names {
            self.tiers.insert(n.to_string(), Tier::Constitutional);
        }
        self
    }
    pub fn default_tier(mut self, tier: Tier) -> Self {
        self.default_tier = tier;
        self
    }
    pub fn signer(mut self, signer: Box<dyn Signer>) -> Self {
        self.signer = Some(signer);
        self
    }
    pub fn sink(mut self, sink: Box<dyn EventSink>) -> Self {
        self.sink = Some(sink);
        self
    }
    pub fn build(self) -> Result<Constitution> {
        fs::create_dir_all(&self.dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700));
        }
        Ok(Constitution {
            journal_path: self
                .journal_path
                .unwrap_or_else(|| self.dir.join("amendments.jsonl")),
            dir: self.dir,
            tiers: self.tiers,
            default_tier: self.default_tier,
            signer: self.signer,
            sink: self.sink,
            lock: Mutex::new(()),
        })
    }
}

impl Constitution {
    /// Begin building a constitution rooted at `dir` (artifacts land in
    /// `<dir>/<id>.json`, the journal alongside as `amendments.jsonl`).
    pub fn builder(dir: impl Into<PathBuf>) -> Builder {
        Builder {
            dir: dir.into(),
            journal_path: None,
            tiers: std::collections::HashMap::new(),
            default_tier: Tier::Statutory,
            signer: None,
            sink: None,
        }
    }

    fn artifact_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Load an amendment artifact.
    pub fn load(&self, id: &str) -> Option<Amendment> {
        let mut buf = String::new();
        fs::File::open(self.artifact_path(id))
            .ok()?
            .read_to_string(&mut buf)
            .ok()?;
        serde_json::from_str(&buf).ok()
    }

    fn save(&self, amendment: &Amendment) -> Result<()> {
        let value = serde_json::to_value(amendment).expect("amendment serializes");
        let tmp = self.artifact_path(&amendment.id).with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(&value)?)?;
        fs::rename(tmp, self.artifact_path(&amendment.id))?;
        Ok(())
    }

    fn journal_tip(&self) -> String {
        let Ok(text) = fs::read_to_string(&self.journal_path) else {
            return "genesis".into();
        };
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .last()
            .and_then(|l| serde_json::from_str::<Value>(l).ok())
            .and_then(|v| v["entry_hash"].as_str().map(String::from))
            .unwrap_or_else(|| "genesis".into())
    }

    fn journal(&self, id: &str, transition: &str, amendment: &Amendment) {
        let artifact = serde_json::to_value(amendment).expect("amendment serializes");
        let artifact_hash = sha256_hex(&canonical(&artifact));
        let mut entry = Map::new();
        entry.insert("ts".into(), iso_now().into());
        entry.insert("amendment_id".into(), id.into());
        entry.insert("transition".into(), transition.into());
        entry.insert("artifact_sha256".into(), artifact_hash.clone().into());
        entry.insert("prev_hash".into(), self.journal_tip().into());
        let mut entry_v = Value::Object(entry.clone());
        let hash = sha256_hex(&canonical(&entry_v));
        entry.insert("entry_hash".into(), hash.into());
        entry_v = Value::Object(entry);
        if let Ok(line) = serde_json::to_string(&entry_v) {
            if let Ok(mut f) = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.journal_path)
            {
                let _ = f.write_all(line.as_bytes());
                let _ = f.write_all(b"\n");
            }
        }
        if let Some(sink) = &self.sink {
            let mut data = Map::new();
            data.insert("amendment_id".into(), id.into());
            data.insert("artifact_sha256".into(), artifact_hash.into());
            sink.emit(&format!("amendment_{transition}"), data);
        }
    }

    fn sign_artifact(&self, amendment: &mut Amendment) {
        let Some(signer) = &self.signer else { return };
        let value = serde_json::to_value(&*amendment).expect("amendment serializes");
        if let Some(sig) = signer.sign(&canonical(&value)) {
            amendment.signature = Some(sig);
            amendment.signed = Some(true);
        }
    }

    /// File a new amendment for `surface`. Returns the amendment id.
    pub fn propose(&self, surface: &str, evidence: Value, proposed_by: &str) -> Result<String> {
        let _guard = self.lock.lock().expect("constitution lock");
        let now = iso_now();
        let id = fresh_id(&now);
        let tier = self
            .tiers
            .get(surface)
            .copied()
            .unwrap_or(self.default_tier);
        let amendment = Amendment {
            kind: "xipe.amendment".into(),
            version: 1,
            id: id.clone(),
            surface: surface.to_string(),
            tier,
            status: Status::Proposed,
            proposed_at: now,
            proposed_by: proposed_by.to_string(),
            evidence,
            council: None,
            ratified_by: None,
            ratified_at: None,
            applied_at: None,
            post_state: None,
            measured: None,
            measured_at: None,
            rejected_by: None,
            rejected_at: None,
            reverted_at: None,
            signature: None,
            signed: None,
            extra: Map::new(),
        };
        self.save(&amendment)?;
        self.journal(&id, "proposed", &amendment);
        Ok(id)
    }

    /// Record the quorum's verdict. Statutory + unanimous auto-ratifies
    /// (signed); constitutional or divided holds for the human.
    pub fn record_verdict(&self, id: &str, verdict: &Verdict) -> Result<Status> {
        let _guard = self.lock.lock().expect("constitution lock");
        let mut amendment = self.load(id).ok_or_else(|| Error::Missing(id.into()))?;
        amendment.council = Some(serde_json::to_value(verdict).expect("verdict serializes"));
        let status = match amendment.tier {
            Tier::Constitutional => Status::Held,
            Tier::Statutory if verdict.unanimous_approve => {
                amendment.ratified_by = Some("quorum-unanimous".into());
                amendment.ratified_at = Some(iso_now());
                Status::Ratified
            }
            Tier::Statutory => Status::Held,
        };
        amendment.status = status;
        if status == Status::Ratified {
            self.sign_artifact(&mut amendment);
        }
        self.save(&amendment)?;
        self.journal(
            id,
            if status == Status::Ratified {
                "deliberated+ratified"
            } else {
                "deliberated+held"
            },
            &amendment,
        );
        Ok(status)
    }

    /// Human ratification — the only path for constitutional-tier and held
    /// amendments. Signs the artifact at ratification.
    pub fn ratify(&self, id: &str) -> Result<Status> {
        let _guard = self.lock.lock().expect("constitution lock");
        let mut amendment = self.load(id).ok_or_else(|| Error::Missing(id.into()))?;
        match amendment.status {
            Status::Held | Status::Proposed => {}
            status => {
                return Err(Error::IllegalTransition {
                    id: id.into(),
                    status,
                    attempted: "ratify",
                })
            }
        }
        amendment.status = Status::Ratified;
        amendment.ratified_by = Some("human".into());
        amendment.ratified_at = Some(iso_now());
        self.sign_artifact(&mut amendment);
        self.save(&amendment)?;
        self.journal(id, "ratified", &amendment);
        Ok(Status::Ratified)
    }

    /// Human rejection of a held or proposed amendment.
    pub fn reject(&self, id: &str) -> Result<Status> {
        let _guard = self.lock.lock().expect("constitution lock");
        let mut amendment = self.load(id).ok_or_else(|| Error::Missing(id.into()))?;
        match amendment.status {
            Status::Held | Status::Proposed => {}
            status => {
                return Err(Error::IllegalTransition {
                    id: id.into(),
                    status,
                    attempted: "reject",
                })
            }
        }
        amendment.status = Status::Rejected;
        amendment.rejected_by = Some("human".into());
        amendment.rejected_at = Some(iso_now());
        self.save(&amendment)?;
        self.journal(id, "rejected", &amendment);
        Ok(Status::Rejected)
    }

    /// Mark the amendment applied — the caller performed the surface
    /// mutation. `post_state` carries fingerprints of what changed.
    pub fn mark_applied(&self, id: &str, post_state: Value) -> Result<()> {
        let _guard = self.lock.lock().expect("constitution lock");
        let mut amendment = self.load(id).ok_or_else(|| Error::Missing(id.into()))?;
        if amendment.status != Status::Ratified {
            return Err(Error::IllegalTransition {
                id: id.into(),
                status: amendment.status,
                attempted: "apply",
            });
        }
        amendment.status = Status::Applied;
        amendment.applied_at = Some(iso_now());
        amendment.post_state = Some(post_state);
        self.save(&amendment)?;
        self.journal(id, "applied", &amendment);
        Ok(())
    }

    /// Attach post-apply measurement — what the amendment actually did.
    pub fn mark_measured(&self, id: &str, metrics: Value) -> Result<()> {
        let _guard = self.lock.lock().expect("constitution lock");
        let mut amendment = self.load(id).ok_or_else(|| Error::Missing(id.into()))?;
        if amendment.status != Status::Applied {
            return Err(Error::IllegalTransition {
                id: id.into(),
                status: amendment.status,
                attempted: "measure",
            });
        }
        amendment.measured = Some(metrics);
        amendment.measured_at = Some(iso_now());
        self.save(&amendment)?;
        self.journal(id, "measured", &amendment);
        Ok(())
    }

    /// Mark an applied amendment reverted after its mutation was rolled
    /// back. The amendment remains permanently on the record.
    pub fn mark_reverted(&self, id: &str) -> Result<()> {
        let _guard = self.lock.lock().expect("constitution lock");
        let mut amendment = self.load(id).ok_or_else(|| Error::Missing(id.into()))?;
        if amendment.status != Status::Applied {
            return Err(Error::IllegalTransition {
                id: id.into(),
                status: amendment.status,
                attempted: "revert",
            });
        }
        amendment.status = Status::Reverted;
        amendment.reverted_at = Some(iso_now());
        self.save(&amendment)?;
        self.journal(id, "reverted", &amendment);
        Ok(())
    }

    /// List amendments, newest first.
    pub fn list(&self, limit: usize) -> Result<Vec<Amendment>> {
        let mut out = Vec::new();
        let mut names: Vec<_> = fs::read_dir(&self.dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".json"))
            .collect();
        names.sort();
        for name in names.into_iter().rev().take(limit) {
            let id = name.trim_end_matches(".json");
            if let Some(a) = self.load(id) {
                out.push(a);
            }
        }
        Ok(out)
    }

    /// Journal entries for one amendment, in order — its provenance
    /// timeline: proposed, deliberated, ratified, applied, measured, ...
    pub fn history(&self, id: &str) -> Result<Vec<Map<String, Value>>> {
        let text = match fs::read_to_string(&self.journal_path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        Ok(text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["amendment_id"].as_str() == Some(id))
            .filter_map(|v| v.as_object().cloned())
            .collect())
    }

    /// Verify an artifact file against the journal's most recent committed
    /// `artifact_sha256` for that amendment. The journal commits the artifact
    /// hash at every transition — a file that no longer hashes to its last
    /// committed state has been modified outside the lifecycle.
    pub fn verify_artifact(&self, id: &str) -> Result<()> {
        let amendment = self.load(id).ok_or_else(|| Error::Missing(id.into()))?;
        let history = self.history(id)?;
        let last = history.last().ok_or(Error::JournalCorrupt {
            line: 0,
            reason: format!("no journal entries for {id}"),
        })?;
        let committed = last["artifact_sha256"].as_str().unwrap_or("");
        let value = serde_json::to_value(&amendment)?;
        let actual = sha256_hex(&canonical(&value));
        if actual != committed {
            return Err(Error::JournalCorrupt {
                line: 0,
                reason: format!("artifact {id} hashes {actual}, journal committed {committed}"),
            });
        }
        Ok(())
    }

    /// Verify the journal chain AND every artifact's committed hash.
    /// The complete integrity pass.
    pub fn verify_all(&self) -> Result<()> {
        self.verify_journal()?;
        for amendment in self.list(usize::MAX)? {
            self.verify_artifact(&amendment.id)?;
        }
        Ok(())
    }

    /// Re-verify the hash-chained journal end to end: every entry's hash
    /// recomputes and every `prev_hash` links to its predecessor.
    pub fn verify_journal(&self) -> Result<()> {
        let text = match fs::read_to_string(&self.journal_path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let mut prev = "genesis".to_string();
        for (i, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: Value = serde_json::from_str(line).map_err(|e| Error::JournalCorrupt {
                line: i + 1,
                reason: format!("invalid json: {e}"),
            })?;
            let claimed_hash = entry["entry_hash"].as_str().unwrap_or("").to_string();
            let claimed_prev = entry["prev_hash"].as_str().unwrap_or("").to_string();
            if claimed_prev != prev {
                return Err(Error::JournalCorrupt {
                    line: i + 1,
                    reason: format!("prev_hash {claimed_prev} != expected {prev}"),
                });
            }
            let mut body = entry.clone();
            body.as_object_mut().map(|m| m.remove("entry_hash"));
            if sha256_hex(&canonical(&body)) != claimed_hash {
                return Err(Error::JournalCorrupt {
                    line: i + 1,
                    reason: "entry_hash mismatch".into(),
                });
            }
            prev = claimed_hash;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct NoSigner;
    impl Signer for NoSigner {
        fn sign(&self, _: &[u8]) -> Option<Signature> {
            Some(Signature {
                scheme: "test".into(),
                pubkey: "deadbeef".into(),
                sig: "cafe".into(),
            })
        }
    }

    fn constitution(dir: &std::path::Path) -> Constitution {
        Constitution::builder(dir)
            .constitutional(&["policy_patch", "gate_change"])
            .signer(Box::new(NoSigner))
            .build()
            .unwrap()
    }

    fn unanimous() -> Verdict {
        Verdict {
            decision: "approve".into(),
            mean: 1.0,
            dissent: 0.0,
            unanimous_approve: true,
            summary: "4/4 approve".into(),
            votes: vec![],
        }
    }

    #[test]
    fn statutory_unanimous_auto_ratifies_and_signs() {
        let dir = std::env::temp_dir().join(format!("xipe-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let c = constitution(&dir);
        let id = c
            .propose(
                "weight_graft",
                serde_json::json!({"sha256": "abc"}),
                "dream",
            )
            .unwrap();
        assert_eq!(
            c.record_verdict(&id, &unanimous()).unwrap(),
            Status::Ratified
        );
        let a = c.load(&id).unwrap();
        assert_eq!(a.ratified_by.as_deref(), Some("quorum-unanimous"));
        assert_eq!(a.signed, Some(true));
        c.mark_applied(&id, json!({"adapter_sha256": "abc"}))
            .unwrap();
        c.mark_measured(&id, json!({"val_loss": "0.9→0.8"}))
            .unwrap();
        c.mark_reverted(&id).unwrap();
        c.verify_journal().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn contested_statutory_holds_for_human() {
        let dir = std::env::temp_dir().join(format!("xipe-test-h-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let c = constitution(&dir);
        let id = c.propose("prompt_patch", json!({}), "curious").unwrap();
        let divided = Verdict {
            unanimous_approve: false,
            dissent: 0.25,
            ..unanimous()
        };
        assert_eq!(c.record_verdict(&id, &divided).unwrap(), Status::Held);
        assert!(c.mark_applied(&id, json!({})).is_err());
        c.ratify(&id).unwrap();
        c.mark_applied(&id, json!({})).unwrap();
        c.verify_journal().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn constitutional_never_self_ratifies() {
        let dir = std::env::temp_dir().join(format!("xipe-test-c-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let c = constitution(&dir);
        let id = c.propose("policy_patch", json!({}), "council").unwrap();
        // Even a unanimous council cannot ratify the rules that bind it.
        assert_eq!(c.record_verdict(&id, &unanimous()).unwrap(), Status::Held);
        c.ratify(&id).unwrap();
        assert_eq!(c.load(&id).unwrap().ratified_by.as_deref(), Some("human"));
        c.verify_journal().unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn artifact_tamper_detected() {
        let dir = std::env::temp_dir().join(format!("xipe-test-at-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let c = constitution(&dir);
        let id = c.propose("x", json!({}), "me").unwrap();
        c.record_verdict(&id, &unanimous()).unwrap();
        c.verify_artifact(&id).unwrap();
        // Forge the artifact on disk — status flipped behind the journal's back.
        let path = dir.join(format!("{id}.json"));
        let text = fs::read_to_string(&path)
            .unwrap()
            .replace("ratified", "applied");
        fs::write(&path, text).unwrap();
        assert!(matches!(
            c.verify_artifact(&id),
            Err(Error::JournalCorrupt { .. })
        ));
        assert!(matches!(c.verify_all(), Err(Error::JournalCorrupt { .. })));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_returns_ordered_transitions() {
        let dir = std::env::temp_dir().join(format!("xipe-test-hi-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let c = constitution(&dir);
        let id = c.propose("x", json!({}), "me").unwrap();
        c.record_verdict(&id, &unanimous()).unwrap();
        c.mark_applied(&id, json!({})).unwrap();
        let history = c.history(&id).unwrap();
        let transitions: Vec<_> = history
            .iter()
            .filter_map(|e| e["transition"].as_str())
            .collect();
        assert_eq!(
            transitions,
            vec!["proposed", "deliberated+ratified", "applied"]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_votes_computes_unanimity_and_dissent() {
        let approve = |seat: &str| Vote {
            seat: seat.into(),
            vote: "approve".into(),
            rationale: String::new(),
        };
        let deny = Vote {
            seat: "d".into(),
            vote: "deny".into(),
            rationale: "risk".into(),
        };
        let v = Verdict::from_votes(
            vec![approve("a"), approve("b"), approve("c")],
            "approve",
            "3/3",
        );
        assert!(v.unanimous_approve);
        assert_eq!(v.mean, 1.0);
        let v = Verdict::from_votes(vec![approve("a"), deny, approve("c")], "approve", "2/3");
        assert!(!v.unanimous_approve);
        assert!((v.mean - 0.666).abs() < 0.01);
        assert!((v.dissent - 0.333).abs() < 0.01);
        // Empty quorum never ratifies itself.
        assert!(!Verdict::from_votes(vec![], "approve", "").unanimous_approve);
    }

    #[test]
    fn journal_detects_tampering() {
        let dir = std::env::temp_dir().join(format!("xipe-test-t-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let c = constitution(&dir);
        let id = c.propose("x", json!({}), "me").unwrap();
        c.record_verdict(&id, &unanimous()).unwrap();
        // Forge the first journal line.
        let journal = dir.join("amendments.jsonl");
        let mut text = fs::read_to_string(&journal).unwrap();
        text = text.replacen("proposed", "ratified", 1);
        fs::write(&journal, text).unwrap();
        assert!(matches!(
            c.verify_journal(),
            Err(Error::JournalCorrupt { .. })
        ));
        let _ = fs::remove_dir_all(&dir);
    }
}
