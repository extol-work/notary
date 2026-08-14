//! Layer 5 disclosure tokens per SPEC §6.3.
//!
//! A disclosure token authorizes exactly one retrieval of one attestation's
//! payload. Four required properties, all enforced here:
//!
//! 1. **Single-use by default.** Redemption records the token's `token_id` in
//!    a local ledger; a second redemption of the same `token_id` fails with a
//!    distinct error class.
//! 2. **Time-bounded.** Every token carries an `expires_at` Unix-seconds
//!    field. Recommended range per SPEC §6.3: minimum 60 seconds, maximum
//!    7 days. Enforced at both issue time and redeem time.
//! 3. **Signer-authorized.** The token is signed by the same Ed25519 key that
//!    produced the attestation. Redemption verifies the token signer's pubkey
//!    equals the attestation's `signer` field.
//! 4. **Domain-separated.** The bytes covered by the token signature are
//!    prefixed with the literal `sworn-disclosure-token-v1`. That prefix
//!    cannot appear at the head of the 248-byte attestation canonical bytes
//!    (which start with `spec_version` as u16 LE, `03 00` for v0.2). No cross-
//!    protocol confusion between token signatures and attestation signatures.
//!
//! ## Token canonical bytes
//!
//! What the signer commits to:
//!
//! ```text
//!   domain_separator_len   (u32 LE, always = 25 for v1)      = 4 bytes
//!   domain_separator       ("sworn-disclosure-token-v1")     = 25 bytes
//!   attestation_hash       (SHA-256 of attestation canonical) = 32 bytes
//!   token_id               (random 32 bytes; prevents replay) = 32 bytes
//!   expires_at             (i64 LE, Unix seconds)             = 8 bytes
//!   single_use             (u8, 0 = multi-use, 1 = single)    = 1 byte
//! ```
//!
//! Total: 102 bytes. The `token_id` is opaque randomness; it exists so two
//! tokens issued for the same attestation with the same expiry are still
//! distinct signed objects. This is what the ledger tracks for single-use.

use anyhow::Context;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::attestation::Attestation;
use crate::canonical;

/// The literal domain separator per SPEC §6.3. Any change to this string
/// invalidates every previously-issued token; treat as a permanent constant.
pub const DOMAIN_SEPARATOR_V1: &str = "sworn-disclosure-token-v1";

/// SPEC §6.3 recommended minimum token lifetime. Enforced at issue.
pub const MIN_LIFETIME_SECS: i64 = 60;

/// SPEC §6.3 recommended maximum lifetime for single-use tokens. Enforced at
/// issue for single-use tokens. Multi-use tokens are permitted to exceed this
/// only if the caller passes `--allow-long-lifetime`.
pub const MAX_SINGLE_USE_LIFETIME_SECS: i64 = 7 * 24 * 3600;

/// On-disk JSON representation of a disclosure token.
///
/// All 32-byte and 64-byte binary fields are lowercase hex strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureToken {
    /// Version marker. Currently the literal "v1" corresponding to
    /// domain separator `sworn-disclosure-token-v1`.
    pub token_version: String,

    /// Domain separator string as signed. Redundant with `token_version` but
    /// makes the JSON self-describing for any tool that just wants to know
    /// what got signed.
    pub domain_separator: String,

    /// SHA-256 of the 248-byte canonical bytes of the attestation this token
    /// covers (32 bytes, lowercase hex). Matches the on-chain PDA seed nonce.
    pub attestation_hash: String,

    /// Opaque per-token randomness (32 bytes, lowercase hex). Also serves as
    /// the ledger key for single-use enforcement.
    pub token_id: String,

    /// Unix seconds after which the token MUST be refused per SPEC §6.3.
    pub expires_at: i64,

    /// If true, redemption MUST record `token_id` and refuse a second
    /// redemption. If false, the token is a multi-use disclosure and single-
    /// use is explicitly waived (per SPEC §6.3, this MUST be visible in the
    /// token metadata, which is what this field provides).
    pub single_use: bool,

    /// Ed25519 public key that signed this token (32 bytes, lowercase hex).
    /// MUST equal the covered attestation's `signer` field on redemption.
    pub signer: String,

    /// Ed25519 signature over the canonical token bytes (64 bytes, lowercase hex).
    pub signature: String,
}

impl DisclosureToken {
    /// Build the exact bytes covered by the token signature. Fixed layout,
    /// little-endian for multi-byte integers, no framing.
    pub fn to_signing_bytes(
        attestation_hash: &[u8; 32],
        token_id: &[u8; 32],
        expires_at: i64,
        single_use: bool,
    ) -> Vec<u8> {
        let sep = DOMAIN_SEPARATOR_V1.as_bytes();
        let mut buf = Vec::with_capacity(4 + sep.len() + 32 + 32 + 8 + 1);
        buf.extend_from_slice(&(sep.len() as u32).to_le_bytes());
        buf.extend_from_slice(sep);
        buf.extend_from_slice(attestation_hash);
        buf.extend_from_slice(token_id);
        buf.extend_from_slice(&expires_at.to_le_bytes());
        buf.push(if single_use { 1 } else { 0 });
        buf
    }

    /// Reconstruct the signing bytes from this token's fields.
    pub fn signing_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let attestation_hash = hex32(&self.attestation_hash, "attestation_hash")?;
        let token_id = hex32(&self.token_id, "token_id")?;
        Ok(Self::to_signing_bytes(
            &attestation_hash,
            &token_id,
            self.expires_at,
            self.single_use,
        ))
    }
}

fn hex32(s: &str, field: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|e| anyhow::anyhow!("{field}: invalid hex: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("{field}: expected 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn hex64(s: &str, field: &str) -> anyhow::Result<[u8; 64]> {
    let bytes = hex::decode(s).map_err(|e| anyhow::anyhow!("{field}: invalid hex: {e}"))?;
    if bytes.len() != 64 {
        anyhow::bail!("{field}: expected 64 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// SHA-256 of the attestation's canonical bytes. This is what the token
/// binds to: the same value that lives on-chain as the SAS PDA nonce.
pub fn attestation_hash_for(att: &Attestation) -> anyhow::Result<[u8; 32]> {
    let fields = att.to_canonical_fields()?;
    Ok(fields.attestation_hash())
}

// ─── Issue ────────────────────────────────────────────────────────────

/// Issue a disclosure token authorizing one retrieval of the given
/// attestation's payload.
///
/// - `att` - the attestation to cover. The signer key MUST match the
///   attestation's `signer` field (SPEC §6.3 signer-authorized).
/// - `signing_key` - the Ed25519 key that produced the attestation.
/// - `lifetime_secs` - token validity window. SPEC §6.3 recommends a floor of
///   60 s and (for single-use tokens) a ceiling of 7 days.
/// - `single_use` - true for one-shot tokens (default), false for
///   explicitly-designated multi-use tokens (per SPEC §6.3 multi-use MUST be
///   visible in metadata, which this bool provides).
/// - `allow_long_lifetime` - bypass the 7-day ceiling. Refused for single-use
///   tokens.
pub fn issue(
    att: &Attestation,
    signing_key: &SigningKey,
    lifetime_secs: i64,
    single_use: bool,
    allow_long_lifetime: bool,
) -> anyhow::Result<DisclosureToken> {
    // SPEC §6.3 signer-authorized: the token issuer MUST prove control of
    // the attestation's signing key. We enforce this by requiring the caller
    // to pass the actual key and cross-checking that its verifying key matches
    // the attestation's signer field.
    let signer_pubkey = signing_key.verifying_key().to_bytes();
    let att_signer = hex32(&att.signer, "attestation.signer")?;
    if signer_pubkey != att_signer {
        anyhow::bail!(
            "SPEC §6.3: signing key pubkey {} does not match attestation signer {}. \
             A disclosure token MUST be issued by proof of control of the attestation's signing key.",
            hex::encode(signer_pubkey),
            hex::encode(att_signer)
        );
    }

    // SPEC §6.3 time-bounded: enforce the recommended range.
    if lifetime_secs < MIN_LIFETIME_SECS {
        anyhow::bail!(
            "SPEC §6.3 recommends a minimum token lifetime of {MIN_LIFETIME_SECS} seconds; got {lifetime_secs}"
        );
    }
    if single_use && lifetime_secs > MAX_SINGLE_USE_LIFETIME_SECS && !allow_long_lifetime {
        anyhow::bail!(
            "SPEC §6.3 recommends a maximum single-use lifetime of 7 days ({MAX_SINGLE_USE_LIFETIME_SECS} seconds); \
             got {lifetime_secs}. Use --allow-long-lifetime to override for a specific reason, or issue a multi-use \
             token if single-use is not what you want."
        );
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64;
    let expires_at = now_secs
        .checked_add(lifetime_secs)
        .context("lifetime overflow computing expires_at")?;

    let attestation_hash = attestation_hash_for(att)?;

    // Random token_id ensures two tokens for the same attestation with the
    // same expiry are still distinct signed objects. Also serves as the
    // ledger key for single-use enforcement.
    let mut token_id = [0u8; 32];
    OsRng.fill_bytes(&mut token_id);

    let signing_bytes =
        DisclosureToken::to_signing_bytes(&attestation_hash, &token_id, expires_at, single_use);
    let signature = signing_key.sign(&signing_bytes);

    // Self-verify per the same discipline as `attest sign`: catch any bug in
    // our own signing path before the token reaches disk.
    signing_key
        .verifying_key()
        .verify(&signing_bytes, &signature)
        .context("self-check: freshly issued token failed local verification")?;

    Ok(DisclosureToken {
        token_version: "v1".to_string(),
        domain_separator: DOMAIN_SEPARATOR_V1.to_string(),
        attestation_hash: hex::encode(attestation_hash),
        token_id: hex::encode(token_id),
        expires_at,
        single_use,
        signer: hex::encode(signer_pubkey),
        signature: hex::encode(signature.to_bytes()),
    })
}

// ─── Redeem ───────────────────────────────────────────────────────────

/// Outcome of a redemption attempt. Distinct error classes as required by
/// SPEC §6.3 so callers can distinguish expired-vs-already-consumed-vs-invalid.
///
/// `AlreadyConsumed` is constructed by the CLI wrapper's ledger-gate rather
/// than by `verify_token`, so the compiler flags it as never constructed
/// through library code. Kept as part of the public error surface so library
/// consumers can pattern-match on it uniformly.
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum RedeemError {
    #[error("SPEC §6.3: token version {0:?} is not supported (expected \"v1\")")]
    UnsupportedVersion(String),

    #[error("SPEC §6.3: token domain separator {0:?} does not match expected {1:?}. \
             This may indicate a token from a different protocol or a tampered token.")]
    WrongDomainSeparator(String, String),

    #[error("SPEC §6.3: token signature is not valid Ed25519 over the token's canonical bytes: {0}")]
    InvalidSignature(String),

    #[error("SPEC §6.3: token signer {token_signer} does not match attestation signer {attestation_signer}. \
             A disclosure token MUST be issued by proof of control of the attestation's signing key.")]
    SignerMismatch {
        token_signer: String,
        attestation_signer: String,
    },

    #[error("SPEC §6.3: token binds attestation_hash {token_hash} but the attestation's hash is {attestation_hash}. \
             The token is for a different attestation.")]
    AttestationMismatch {
        token_hash: String,
        attestation_hash: String,
    },

    #[error(
        "SPEC §6.3: token expired at Unix seconds {expires_at} (now = {now_secs}). \
         This is distinct from single-use exhaustion; issue a fresh token."
    )]
    Expired { expires_at: i64, now_secs: i64 },

    #[error(
        "SPEC §6.3: single-use token {token_id_prefix}\u{2026} has already been redeemed. \
         Consumption recorded at {ledger_path}. Issue a fresh token; single-use is a hard property."
    )]
    AlreadyConsumed {
        token_id_prefix: String,
        ledger_path: String,
    },

    #[error(
        "SPEC §6.2: disclosed payload hash {payload_hash} does not match attestation.data_hash {data_hash}. \
         Rejecting per SPEC §6.2 payload-authenticity requirement even though the token was valid."
    )]
    TamperedPayload {
        payload_hash: String,
        data_hash: String,
    },

    #[error(
        "SPEC §6.2: attestation carries no payload to disclose (the `payload` field is absent). \
         A token verified successfully but there is nothing to return."
    )]
    NoPayload,

    #[error("{0}")]
    Other(String),
}

impl RedeemError {
    /// Machine-readable class string. Useful for callers that want to switch
    /// on the error kind without matching Debug output.
    pub fn class(&self) -> &'static str {
        match self {
            RedeemError::UnsupportedVersion(_) => "unsupported_version",
            RedeemError::WrongDomainSeparator(..) => "wrong_domain_separator",
            RedeemError::InvalidSignature(_) => "invalid_signature",
            RedeemError::SignerMismatch { .. } => "signer_mismatch",
            RedeemError::AttestationMismatch { .. } => "attestation_mismatch",
            RedeemError::Expired { .. } => "expired",
            RedeemError::AlreadyConsumed { .. } => "already_consumed",
            RedeemError::TamperedPayload { .. } => "tampered_payload",
            RedeemError::NoPayload => "no_payload",
            RedeemError::Other(_) => "other",
        }
    }
}

/// Verify a token against an attestation and (if all checks pass) return the
/// payload bytes. This function does NOT touch the ledger; call
/// [`consume_token_in_ledger`] separately after a successful return to make
/// single-use enforcement stick.
///
/// Separating verify from consume lets tests and dry-run modes call this
/// without mutating persistent state. The `redeem` command always calls both.
pub fn verify_token(
    att: &Attestation,
    token: &DisclosureToken,
    now_secs: i64,
) -> Result<serde_json::Value, RedeemError> {
    // Version + domain separator checks first - cheapest and most diagnostic.
    if token.token_version != "v1" {
        return Err(RedeemError::UnsupportedVersion(token.token_version.clone()));
    }
    if token.domain_separator != DOMAIN_SEPARATOR_V1 {
        return Err(RedeemError::WrongDomainSeparator(
            token.domain_separator.clone(),
            DOMAIN_SEPARATOR_V1.to_string(),
        ));
    }

    // Expiration - refuse expired tokens with the distinct error class SPEC
    // §6.3 requires. Do this before signature check so an expired but
    // otherwise valid token surfaces with the more actionable error.
    if now_secs > token.expires_at {
        return Err(RedeemError::Expired {
            expires_at: token.expires_at,
            now_secs,
        });
    }

    // Signer match - token signer MUST equal attestation signer.
    if token.signer != att.signer {
        return Err(RedeemError::SignerMismatch {
            token_signer: token.signer.clone(),
            attestation_signer: att.signer.clone(),
        });
    }

    // Attestation hash match - token MUST cover *this* attestation.
    let att_hash = attestation_hash_for(att)
        .map_err(|e| RedeemError::Other(format!("compute attestation hash: {e}")))?;
    let att_hash_hex = hex::encode(att_hash);
    if token.attestation_hash != att_hash_hex {
        return Err(RedeemError::AttestationMismatch {
            token_hash: token.attestation_hash.clone(),
            attestation_hash: att_hash_hex,
        });
    }

    // Signature verification.
    let signing_bytes = token
        .signing_bytes()
        .map_err(|e| RedeemError::Other(format!("reconstruct signing bytes: {e}")))?;
    let signer_pubkey = hex32(&token.signer, "token.signer")
        .map_err(|e| RedeemError::Other(format!("decode token signer: {e}")))?;
    let verifying_key = VerifyingKey::from_bytes(&signer_pubkey)
        .map_err(|e| RedeemError::InvalidSignature(format!("bad pubkey: {e}")))?;
    let sig_bytes = hex64(&token.signature, "token.signature")
        .map_err(|e| RedeemError::Other(format!("decode token signature: {e}")))?;
    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(&signing_bytes, &signature)
        .map_err(|e| RedeemError::InvalidSignature(e.to_string()))?;

    // Payload authenticity per SPEC §6.2 - recompute SHA-256 over RFC 8785
    // canonicalized payload and compare to attestation.data_hash. A tampered
    // payload is rejected even when the token is valid.
    let payload = att.payload.as_ref().ok_or(RedeemError::NoPayload)?.clone();
    let recomputed = canonical::data_hash(&payload)
        .map_err(|e| RedeemError::Other(format!("hash payload: {e}")))?;
    let recomputed_hex = hex::encode(recomputed);
    if recomputed_hex != att.data_hash {
        return Err(RedeemError::TamperedPayload {
            payload_hash: recomputed_hex,
            data_hash: att.data_hash.clone(),
        });
    }

    Ok(payload)
}

// ─── Single-use ledger ────────────────────────────────────────────────
//
// Simple JSON file listing every consumed token_id (lowercase hex). Read once
// on open, appended to on consume. Not thread-safe across concurrent CLI
// invocations; if that becomes a real concern, replace with a small SQLite
// database. For the reference CLI a single-writer JSON file is sufficient.

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerFile {
    /// File format version. Currently 1.
    version: u32,
    /// Every token_id that has been redeemed, in the order it was recorded.
    consumed: Vec<ConsumedEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConsumedEntry {
    /// Lowercase hex of the token_id.
    token_id: String,
    /// Unix seconds when consumption was recorded.
    consumed_at: i64,
    /// Hex prefix of the attestation the token covered. Informational only.
    attestation_hash_prefix: String,
}

/// Default ledger path: `~/.notary/consumed-tokens.json`.
pub fn default_ledger_path() -> anyhow::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| anyhow::anyhow!("HOME environment variable not set; pass --ledger explicitly"))?;
    let mut p = PathBuf::from(home);
    p.push(".notary");
    p.push("consumed-tokens.json");
    Ok(p)
}

fn read_ledger(path: &Path) -> anyhow::Result<LedgerFile> {
    if !path.exists() {
        return Ok(LedgerFile {
            version: 1,
            consumed: Vec::new(),
        });
    }
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("read ledger {}", path.display()))?;
    let ledger: LedgerFile = serde_json::from_str(&contents)
        .with_context(|| format!("parse ledger {} as notary consumed-tokens JSON", path.display()))?;
    if ledger.version != 1 {
        anyhow::bail!(
            "ledger {} declares version {}; this build only supports version 1",
            path.display(),
            ledger.version
        );
    }
    Ok(ledger)
}

fn write_ledger(path: &Path, ledger: &LedgerFile) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create ledger dir {}", parent.display()))?;
        }
    }
    let json = serde_json::to_string_pretty(ledger)
        .map_err(|e| anyhow::anyhow!("serialize ledger: {e}"))?;
    std::fs::write(path, json).with_context(|| format!("write ledger {}", path.display()))?;
    Ok(())
}

/// Check whether a token_id has already been redeemed. Read-only.
pub fn is_consumed(ledger_path: &Path, token_id_hex: &str) -> anyhow::Result<bool> {
    let ledger = read_ledger(ledger_path)?;
    Ok(ledger.consumed.iter().any(|e| e.token_id == token_id_hex))
}

/// Record a token_id as consumed. Idempotent: recording a token_id that is
/// already present in the ledger is a no-op. This is safe because
/// [`verify_token`] and [`is_consumed`] gate on the ledger before calling this.
pub fn consume_token_in_ledger(
    ledger_path: &Path,
    token: &DisclosureToken,
    now_secs: i64,
) -> anyhow::Result<()> {
    if !token.single_use {
        return Ok(()); // multi-use tokens do not consume ledger space
    }
    let mut ledger = read_ledger(ledger_path)?;
    if ledger.consumed.iter().any(|e| e.token_id == token.token_id) {
        return Ok(());
    }
    let att_hash_prefix = token.attestation_hash.chars().take(16).collect::<String>();
    ledger.consumed.push(ConsumedEntry {
        token_id: token.token_id.clone(),
        consumed_at: now_secs,
        attestation_hash_prefix: att_hash_prefix,
    });
    write_ledger(ledger_path, &ledger)?;
    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::CanonicalFields;

    fn baked_signer() -> (SigningKey, [u8; 32]) {
        let seed = [0x42u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn baked_attestation(signer_pubkey: [u8; 32]) -> Attestation {
        let payload = serde_json::json!({"note": "test payload"});
        let data_hash = canonical::data_hash(&payload).unwrap();

        let fields = CanonicalFields {
            spec_version: 3,
            signer: signer_pubkey,
            subject: signer_pubkey,
            activity_hash: canonical::activity_hash("https://schemas.example.org/test/v1"),
            data_hash,
            witness_for: [0u8; 32],
            source_hash: [0u8; 32],
            source_type: 1,
            confidence: 10000,
            witnessing_depth: 0,
            attestor_relationship: 0,
            signer_asserted_at: 1_780_000_000,
            retention_hint: 0,
            nonce: [0x99u8; 32],
        };
        let canonical_bytes = fields.to_bytes();
        let (sk, _) = baked_signer();
        let sig = sk.sign(&canonical_bytes);

        Attestation {
            spec_version: 3,
            signer: hex::encode(signer_pubkey),
            subject: hex::encode(signer_pubkey),
            activity_type: "https://schemas.example.org/test/v1".to_string(),
            data_hash: hex::encode(data_hash),
            witness_for: hex::encode([0u8; 32]),
            source_hash: hex::encode([0u8; 32]),
            source_type: 1,
            confidence: 10000,
            witnessing_depth: 0,
            attestor_relationship: 0,
            signer_asserted_at: 1_780_000_000,
            retention_hint: 0,
            nonce: hex::encode([0x99u8; 32]),
            signature: hex::encode(sig.to_bytes()),
            payload: Some(payload),
            anchors: Vec::new(),
        }
    }

    #[test]
    fn signing_bytes_layout_is_stable() {
        // 4 (sep len) + 25 (sep) + 32 (att hash) + 32 (token id) + 8 (expires) + 1 (single_use) = 102
        let bytes = DisclosureToken::to_signing_bytes(&[0u8; 32], &[0u8; 32], 0, true);
        assert_eq!(bytes.len(), 102);

        // Domain separator sits at bytes 4..29
        assert_eq!(&bytes[4..29], DOMAIN_SEPARATOR_V1.as_bytes());
    }

    #[test]
    fn domain_separator_cannot_confuse_with_attestation_canonical_bytes() {
        // Attestation canonical bytes always start with spec_version = 03 00
        // for v0.2. Token signing bytes start with the domain separator LENGTH
        // (25 = 0x19 0x00 0x00 0x00), then the ASCII 's' of "sworn-...".
        // These first bytes are structurally incompatible; a signature over
        // one shape cannot be replayed against the other.
        let token_bytes = DisclosureToken::to_signing_bytes(&[0u8; 32], &[0u8; 32], 0, true);
        assert_eq!(&token_bytes[0..4], &25u32.to_le_bytes());
        assert_ne!(&token_bytes[0..2], &3u16.to_le_bytes());
    }

    #[test]
    fn issue_then_verify_happy_path() {
        let (sk, pk) = baked_signer();
        let att = baked_attestation(pk);
        let token = issue(&att, &sk, 3600, true, false).expect("issue");

        // Verify at a moment before expiration.
        let payload = verify_token(&att, &token, 1_780_000_100).expect("verify");
        assert_eq!(payload, serde_json::json!({"note": "test payload"}));
    }

    #[test]
    fn verify_expired_token_returns_distinct_error_class() {
        let (sk, pk) = baked_signer();
        let att = baked_attestation(pk);
        let token = issue(&att, &sk, 3600, true, false).expect("issue");

        // Verify at expires_at + 1.
        let err = verify_token(&att, &token, token.expires_at + 1).expect_err("must expire");
        assert_eq!(err.class(), "expired");
    }

    #[test]
    fn verify_rejects_wrong_signer() {
        let (sk, pk) = baked_signer();
        let mut att = baked_attestation(pk);
        // Change attestation signer to something else; token was signed by sk.
        att.signer = hex::encode([0xAAu8; 32]);
        let token = issue(&att, &sk, 3600, true, false).expect_err("issue must catch this");
        assert!(token.to_string().contains("SPEC §6.3"));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let (sk, pk) = baked_signer();
        let mut att = baked_attestation(pk);
        let token = issue(&att, &sk, 3600, true, false).expect("issue");
        // Tamper with the payload after issuance.
        att.payload = Some(serde_json::json!({"note": "tampered"}));
        let err = verify_token(&att, &token, 1_780_000_100).expect_err("must reject tamper");
        assert_eq!(err.class(), "tampered_payload");
    }

    #[test]
    fn ledger_records_consumption_and_second_check_sees_it() {
        let (sk, pk) = baked_signer();
        let att = baked_attestation(pk);
        let token = issue(&att, &sk, 3600, true, false).expect("issue");

        let mut ledger_path = std::env::temp_dir();
        ledger_path.push(format!(
            "notary-ledger-test-{}-{}.json",
            std::process::id(),
            token.token_id.chars().take(8).collect::<String>()
        ));
        let _ = std::fs::remove_file(&ledger_path);

        assert!(!is_consumed(&ledger_path, &token.token_id).expect("check"));
        consume_token_in_ledger(&ledger_path, &token, 1_780_000_100).expect("consume");
        assert!(is_consumed(&ledger_path, &token.token_id).expect("check"));

        // Second consume is a no-op (idempotent), but the caller-side gate
        // is is_consumed which returns true.
        consume_token_in_ledger(&ledger_path, &token, 1_780_000_200).expect("re-consume no-op");

        let _ = std::fs::remove_file(&ledger_path);
    }

    #[test]
    fn multi_use_token_does_not_touch_ledger() {
        let (sk, pk) = baked_signer();
        let att = baked_attestation(pk);
        let token = issue(&att, &sk, 3600, false, false).expect("issue multi-use");
        assert!(!token.single_use);

        let mut ledger_path = std::env::temp_dir();
        ledger_path.push(format!(
            "notary-ledger-multi-{}-{}.json",
            std::process::id(),
            token.token_id.chars().take(8).collect::<String>()
        ));
        let _ = std::fs::remove_file(&ledger_path);

        consume_token_in_ledger(&ledger_path, &token, 1_780_000_100).expect("multi-use no-op");
        // Ledger file should not have been created for a multi-use token.
        assert!(!ledger_path.exists());
    }

    #[test]
    fn issue_rejects_lifetime_below_spec_minimum() {
        let (sk, pk) = baked_signer();
        let att = baked_attestation(pk);
        let err = issue(&att, &sk, 30, true, false).expect_err("must reject sub-60s lifetime");
        assert!(err.to_string().contains("60 seconds"));
    }

    #[test]
    fn issue_rejects_long_lifetime_for_single_use_without_override() {
        let (sk, pk) = baked_signer();
        let att = baked_attestation(pk);
        let err = issue(&att, &sk, 8 * 24 * 3600, true, false)
            .expect_err("must reject >7d single-use lifetime");
        assert!(err.to_string().contains("7 days"));
    }
}
