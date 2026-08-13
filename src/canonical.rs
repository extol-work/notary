//! Canonical byte sequence per SPEC §3.1 (v0.2, spec_version = 3).
//!
//! The 248-byte sequence is the ONLY input to Ed25519 signing. Every field
//! MUST appear at the exact offset defined in SPEC §3.1. Additional fields
//! or framing MUST NOT enter the signed bytes.

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

/// spec_version for v0.2 per SPEC §3.1.1.
pub const SPEC_VERSION_V02: u16 = 3;

/// Total length of the canonical byte sequence per SPEC §3.1.
pub const CANONICAL_LEN: usize = 248;

/// Field offsets within the canonical byte sequence. Named per SPEC §3.1.
mod offset {
    pub const SPEC_VERSION: usize = 0; // u16 LE, 2 bytes
    pub const SIGNER: usize = 2; // 32 bytes
    pub const SUBJECT: usize = 34; // 32 bytes
    pub const ACTIVITY_HASH: usize = 66; // 32 bytes
    pub const DATA_HASH: usize = 98; // 32 bytes
    pub const WITNESS_FOR: usize = 130; // 32 bytes
    pub const SOURCE_HASH: usize = 162; // 32 bytes
    pub const SOURCE_TYPE: usize = 194; // u16 LE, 2 bytes
    pub const CONFIDENCE: usize = 196; // u16 LE, 2 bytes
    pub const WITNESSING_DEPTH: usize = 198; // u8, 1 byte
    pub const ATTESTOR_RELATIONSHIP: usize = 199; // u8, 1 byte
    pub const SIGNER_ASSERTED_AT: usize = 200; // i64 LE, 8 bytes
    pub const RETENTION_HINT: usize = 208; // i64 LE, 8 bytes
    pub const NONCE: usize = 216; // 32 bytes
                                  // 216 + 32 = 248
}

/// The 15 fields that compose the canonical byte sequence per SPEC §3.1.
#[derive(Debug, Clone)]
pub struct CanonicalFields {
    pub spec_version: u16,
    pub signer: [u8; 32],
    pub subject: [u8; 32],
    pub activity_hash: [u8; 32],
    pub data_hash: [u8; 32],
    pub witness_for: [u8; 32],
    pub source_hash: [u8; 32],
    pub source_type: u16,
    pub confidence: u16,
    pub witnessing_depth: u8,
    pub attestor_relationship: u8,
    pub signer_asserted_at: i64,
    pub retention_hint: i64,
    pub nonce: [u8; 32],
}

impl CanonicalFields {
    /// Build the exact 248-byte canonical sequence per SPEC §3.1.
    ///
    /// Little-endian for all multi-byte integers. Field order is fixed.
    /// No framing, no separators, no padding.
    pub fn to_bytes(&self) -> [u8; CANONICAL_LEN] {
        let mut buf = [0u8; CANONICAL_LEN];

        buf[offset::SPEC_VERSION..offset::SPEC_VERSION + 2]
            .copy_from_slice(&self.spec_version.to_le_bytes());
        buf[offset::SIGNER..offset::SIGNER + 32].copy_from_slice(&self.signer);
        buf[offset::SUBJECT..offset::SUBJECT + 32].copy_from_slice(&self.subject);
        buf[offset::ACTIVITY_HASH..offset::ACTIVITY_HASH + 32].copy_from_slice(&self.activity_hash);
        buf[offset::DATA_HASH..offset::DATA_HASH + 32].copy_from_slice(&self.data_hash);
        buf[offset::WITNESS_FOR..offset::WITNESS_FOR + 32].copy_from_slice(&self.witness_for);
        buf[offset::SOURCE_HASH..offset::SOURCE_HASH + 32].copy_from_slice(&self.source_hash);
        buf[offset::SOURCE_TYPE..offset::SOURCE_TYPE + 2]
            .copy_from_slice(&self.source_type.to_le_bytes());
        buf[offset::CONFIDENCE..offset::CONFIDENCE + 2]
            .copy_from_slice(&self.confidence.to_le_bytes());
        buf[offset::WITNESSING_DEPTH] = self.witnessing_depth;
        buf[offset::ATTESTOR_RELATIONSHIP] = self.attestor_relationship;
        buf[offset::SIGNER_ASSERTED_AT..offset::SIGNER_ASSERTED_AT + 8]
            .copy_from_slice(&self.signer_asserted_at.to_le_bytes());
        buf[offset::RETENTION_HINT..offset::RETENTION_HINT + 8]
            .copy_from_slice(&self.retention_hint.to_le_bytes());
        buf[offset::NONCE..offset::NONCE + 32].copy_from_slice(&self.nonce);

        buf
    }

    /// SHA-256 over the canonical byte sequence.
    ///
    /// This is the attestation_hash used as the SAS notary nonce per
    /// bindings/sas.md §3.
    pub fn attestation_hash(&self) -> [u8; 32] {
        sha256(&self.to_bytes())
    }
}

/// SHA-256 primitive. Wraps the sha2 crate for uniform call sites.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// activity_hash per SPEC §2.4: SHA-256 of the activity_type URI as UTF-8
/// after Unicode NFC normalization.
pub fn activity_hash(activity_type_uri: &str) -> [u8; 32] {
    let nfc: String = activity_type_uri.nfc().collect();
    sha256(nfc.as_bytes())
}

/// data_hash per SPEC §2.4: SHA-256 of the RFC 8785 canonicalized payload.
///
/// Payload is a JSON value; canonicalization happens here via serde_jcs.
pub fn data_hash(payload: &serde_json::Value) -> anyhow::Result<[u8; 32]> {
    let canonical = serde_jcs::to_vec(payload)
        .map_err(|e| anyhow::anyhow!("RFC 8785 canonicalization failed: {e}"))?;
    Ok(sha256(&canonical))
}

/// Sourceless-attestation sentinel per SPEC §2.4.
///
/// When source_type ∈ {0, 1} (unknown or self_reported), source_hash MUST be
/// exactly 32 zero bytes. Signers MUST NOT populate source_hash for sourceless.
pub const ZERO_HASH: [u8; 32] = [0u8; 32];

/// witness_for absence sentinel per SPEC §2.6.
///
/// 32 zero bytes means the attestation makes a first-order claim about the
/// subject and does not point at another party's claim.
#[allow(dead_code)] // Semantic public constant; used in tests and by future callers.
pub const NO_WITNESS_FOR: [u8; 32] = [0u8; 32];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_length_is_248() {
        let fields = CanonicalFields {
            spec_version: SPEC_VERSION_V02,
            signer: [1u8; 32],
            subject: [2u8; 32],
            activity_hash: [3u8; 32],
            data_hash: [4u8; 32],
            witness_for: NO_WITNESS_FOR,
            source_hash: ZERO_HASH,
            source_type: 1,
            confidence: 10000,
            witnessing_depth: 0,
            attestor_relationship: 0,
            signer_asserted_at: 1723567890,
            retention_hint: 0,
            nonce: [5u8; 32],
        };
        assert_eq!(fields.to_bytes().len(), 248);
    }

    #[test]
    fn spec_version_appears_first_le() {
        let fields = CanonicalFields {
            spec_version: SPEC_VERSION_V02,
            signer: [0u8; 32],
            subject: [0u8; 32],
            activity_hash: [0u8; 32],
            data_hash: [0u8; 32],
            witness_for: NO_WITNESS_FOR,
            source_hash: ZERO_HASH,
            source_type: 0,
            confidence: 0,
            witnessing_depth: 0,
            attestor_relationship: 0,
            signer_asserted_at: 0,
            retention_hint: 0,
            nonce: [0u8; 32],
        };
        let bytes = fields.to_bytes();
        assert_eq!(bytes[0], 3); // low byte
        assert_eq!(bytes[1], 0); // high byte
    }

    #[test]
    fn activity_hash_is_sha256_of_nfc_utf8() {
        let uri = "https://schemas.example.org/statement-of-service/v1";
        let h = activity_hash(uri);
        // Deterministic: computing twice returns the same bytes.
        assert_eq!(h, activity_hash(uri));
        // Not all zeros.
        assert_ne!(h, ZERO_HASH);
    }

    #[test]
    fn data_hash_uses_rfc_8785_canonicalization() {
        // Two logically-equal payloads with different key orderings must produce
        // the same data_hash.
        let a: serde_json::Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        let b: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        assert_eq!(data_hash(&a).unwrap(), data_hash(&b).unwrap());
    }

    #[test]
    fn field_offsets_are_stable() {
        // Regression: any change to a field offset would silently break every
        // signature ever produced. Pinning offsets here catches accidental drift.
        let fields = CanonicalFields {
            spec_version: 0xABCD,
            signer: [0xAA; 32],
            subject: [0xBB; 32],
            activity_hash: [0xCC; 32],
            data_hash: [0xDD; 32],
            witness_for: [0xEE; 32],
            source_hash: [0xFF; 32],
            source_type: 0x1234,
            confidence: 0x5678,
            witnessing_depth: 0x9A,
            attestor_relationship: 0xBC,
            signer_asserted_at: 0x0102030405060708,
            retention_hint: -1,
            nonce: [0x11; 32],
        };
        let b = fields.to_bytes();
        assert_eq!(&b[0..2], &[0xCD, 0xAB]); // spec_version LE
        assert_eq!(b[2], 0xAA); // signer starts
        assert_eq!(b[34], 0xBB); // subject
        assert_eq!(b[66], 0xCC); // activity_hash
        assert_eq!(b[98], 0xDD); // data_hash
        assert_eq!(b[130], 0xEE); // witness_for
        assert_eq!(b[162], 0xFF); // source_hash
        assert_eq!(&b[194..196], &[0x34, 0x12]); // source_type LE
        assert_eq!(&b[196..198], &[0x78, 0x56]); // confidence LE
        assert_eq!(b[198], 0x9A); // witnessing_depth
        assert_eq!(b[199], 0xBC); // attestor_relationship
        assert_eq!(&b[200..208], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]); // i64 LE
        assert_eq!(&b[208..216], &[0xFF; 8]); // retention_hint = -1 as i64 LE
        assert_eq!(b[216], 0x11); // nonce starts
        assert_eq!(b[247], 0x11); // nonce ends
    }
}
