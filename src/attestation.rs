//! Attestation record: the on-disk JSON shape of a signed attestation.
//!
//! The JSON is the transport and storage form. The signed content is the
//! 248-byte canonical byte sequence (see canonical.rs). Verifiers reconstruct
//! the canonical bytes from the JSON fields and check the signature.
//!
//! Serialization discipline:
//!   - All 32-byte and 64-byte binary fields are lowercase hex strings.
//!   - Integer fields are numeric JSON values.
//!   - activity_type is the URI string as authored (NFC-normalized on hash).
//!   - The optional `payload` field is stored verbatim so verifiers can
//!     recompute data_hash independently.

use crate::canonical::{self, CanonicalFields, SPEC_VERSION_V02};
use serde::{Deserialize, Serialize};

/// On-disk JSON representation of an attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub spec_version: u16,

    /// Ed25519 public key (32 bytes, lowercase hex).
    pub signer: String,

    /// Subject: pubkey, content hash, or activity-type-defined identifier (32 bytes, lowercase hex).
    pub subject: String,

    /// URI naming the class of claim.
    pub activity_type: String,

    /// SHA-256 of the RFC 8785 canonicalized payload (32 bytes, lowercase hex).
    pub data_hash: String,

    /// Optional pointer to another party's claim; 32 zero bytes if absent (32 bytes, lowercase hex).
    pub witness_for: String,

    /// SHA-256 of the canonical source identifier; 32 zero bytes if sourceless (32 bytes, lowercase hex).
    pub source_hash: String,

    /// SPEC §9.2. 0 = unknown, 1 = self_reported, etc.
    pub source_type: u16,

    /// Basis points 0..=10000.
    pub confidence: u16,

    /// SPEC §9.3.
    pub witnessing_depth: u8,

    /// SPEC §9.4.
    pub attestor_relationship: u8,

    /// Unix seconds; signer's claim about when they signed.
    pub signer_asserted_at: i64,

    /// 0 = default, -1 = indefinite, positive = expiry seconds.
    pub retention_hint: i64,

    /// 32 bytes, lowercase hex.
    pub nonce: String,

    /// Ed25519 signature (64 bytes, lowercase hex).
    pub signature: String,

    /// Optional payload. If present, verifier MUST confirm SHA-256(RFC 8785(payload)) == data_hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

impl Attestation {
    /// Rebuild the CanonicalFields struct from the on-disk shape.
    ///
    /// Every hex field is validated for length. Numeric fields are read
    /// verbatim. activity_type is hashed on demand (not stored as bytes).
    pub fn to_canonical_fields(&self) -> anyhow::Result<CanonicalFields> {
        Ok(CanonicalFields {
            spec_version: self.spec_version,
            signer: hex32(&self.signer, "signer")?,
            subject: hex32(&self.subject, "subject")?,
            activity_hash: canonical::activity_hash(&self.activity_type),
            data_hash: hex32(&self.data_hash, "data_hash")?,
            witness_for: hex32(&self.witness_for, "witness_for")?,
            source_hash: hex32(&self.source_hash, "source_hash")?,
            source_type: self.source_type,
            confidence: self.confidence,
            witnessing_depth: self.witnessing_depth,
            attestor_relationship: self.attestor_relationship,
            signer_asserted_at: self.signer_asserted_at,
            retention_hint: self.retention_hint,
            nonce: hex32(&self.nonce, "nonce")?,
        })
    }

    /// Enforce every spec-level constraint that a well-formed attestation MUST
    /// satisfy. Called by verify. Called at end of sign as a self-check.
    pub fn validate_shape(&self) -> anyhow::Result<()> {
        if self.spec_version != SPEC_VERSION_V02 {
            anyhow::bail!(
                "spec_version {} is not supported by this build (expected {})",
                self.spec_version,
                SPEC_VERSION_V02
            );
        }
        if self.confidence > 10000 {
            anyhow::bail!(
                "confidence {} exceeds max 10000 basis points (SPEC §2.5)",
                self.confidence
            );
        }
        // SPEC §2.4 sourceless-attestations rule.
        let source_hash_bytes = hex32(&self.source_hash, "source_hash")?;
        if (self.source_type == 0 || self.source_type == 1)
            && source_hash_bytes != canonical::ZERO_HASH
        {
            anyhow::bail!(
                "source_type {} is sourceless but source_hash is nonzero (SPEC §2.4)",
                self.source_type
            );
        }
        Ok(())
    }
}

/// Parse a hex string into a fixed 32-byte array, with a named-field error.
pub fn hex32(s: &str, field: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(s)
        .map_err(|e| anyhow::anyhow!("{field}: invalid hex: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("{field}: expected 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Parse a hex string into a fixed 64-byte array, with a named-field error.
pub fn hex64(s: &str, field: &str) -> anyhow::Result<[u8; 64]> {
    let bytes = hex::decode(s)
        .map_err(|e| anyhow::anyhow!("{field}: invalid hex: {e}"))?;
    if bytes.len() != 64 {
        anyhow::bail!("{field}: expected 64 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
