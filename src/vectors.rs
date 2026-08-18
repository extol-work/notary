//! Golden vector conformance harness.
//!
//! A vector file (see `fixtures/v0.2/vectors.json`) fixes a set of raw input
//! fields and their expected canonical bytes and Ed25519 signatures. Any
//! conforming implementation MUST reproduce the expected bytes and signature
//! byte-for-byte given the same inputs. The harness has two modes:
//!
//! - `emit`  — regenerate the vector file from a deterministic set of test
//!             cases baked into this module. Use when the spec byte layout
//!             changes (e.g., a `spec_version` bump).
//! - `verify` — read a vector file, reconstruct each vector's canonical bytes
//!              and signature from `input_fields` and `signer_secret_seed_hex`,
//!              compare to the expected values. Fail loud on any mismatch.
//!
//! The vector schema mirrors `github.com/extol-work/sworn/fixtures/attestations/`
//! so vectors produced here are directly consumable by the reference runners
//! in that repository.

use crate::canonical::{sha256, CanonicalFields, CANONICAL_LEN, SPEC_VERSION_V02};
use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

// ─── Vector file schema ─────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
pub struct VectorFile {
    pub spec_version: u16,
    pub spec_version_name: String,
    pub canonical_bytes_length: usize,
    pub signature_algorithm: String,
    pub purpose: String,
    pub vectors: Vec<Vector>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Vector {
    pub name: String,
    pub notes: String,
    pub spec_version: u16,
    pub input_fields: InputFields,
    pub signer_secret_seed_hex: String,
    pub expected_canonical_bytes_hex: String,
    pub expected_canonical_bytes_len: usize,
    pub expected_signature_hex: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InputFields {
    pub signer_hex: String,
    pub subject_hex: String,
    pub activity_hash_hex: String,
    pub data_hash_hex: String,
    pub witness_for_hex: String,
    pub source_hash_hex: String,
    pub source_type: u16,
    pub confidence: u16,
    pub witnessing_depth: u8,
    pub attestor_relationship: u8,
    pub signer_asserted_at: i64,
    pub retention_hint: i64,
    pub nonce_hex: String,
}

// ─── Emit ────────────────────────────────────────────────────────────
//
// Six vectors, deterministic. Baked from the same input shapes as
// v0.1-final so a diff of v0.1-final vs v0.2 vectors reveals only the
// spec_version byte change (bytes 0..2: 02 00 → 03 00) and the
// corresponding signature change. Cleanest possible demonstration that
// v0.2 is a version bump with no other byte-layout change.

/// Deterministic vector definitions. Fixed inputs; do not modify without
/// also updating the shipped fixtures/v0.2/vectors.json file.
fn baked_vectors() -> Vec<(&'static str, &'static str, InputFields, &'static str)> {
    vec![
        (
            "orcid_authorship_happy_path",
            "ORCID-sourced authorship attestation. High confidence, computed match \
             (name-anchored against ORCID record), self-attested (subject is signer). \
             Baseline v0.2 case with every field non-zero.",
            InputFields {
                signer_hex: "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c".into(),
                subject_hex: "0202020202020202020202020202020202020202020202020202020202020202".into(),
                activity_hash_hex: "fa98877fd71ce3a58ded325e04757be78e4c1a9dd6bdf233d9161fdfbd1bbedb".into(),
                data_hash_hex: "8823e4b130074352eca15920d6551b711618d8ea0e5c9c2e82d54c0b8d50914f".into(),
                witness_for_hex: "0000000000000000000000000000000000000000000000000000000000000000".into(),
                source_hash_hex: "1dad02f27ebc996207f39eddf23f6b298935f710a789bd50dd703642ffecd021".into(),
                source_type: 2,
                confidence: 9500,
                witnessing_depth: 4,
                attestor_relationship: 1,
                signer_asserted_at: 1780000000,
                retention_hint: -1,
                nonce_hex: "0808080808080808080808080808080808080808080808080808080808080808".into(),
            },
            "0101010101010101010101010101010101010101010101010101010101010101",
        ),
        (
            "self_reported_sourceless",
            "Self-reported contribution with no external source. source_hash and \
             witness_for both 32 zero bytes. source_type = self_reported (1), \
             witnessing_depth = self_asserted (5), attestor_relationship = self (1). \
             Exercises the SPEC §2.4 zero-source-hash rule.",
            InputFields {
                signer_hex: "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394".into(),
                subject_hex: "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394".into(),
                activity_hash_hex: "a1846c287c6b2e7ee5ccf9254edf8cdba6faa0eadb3dee325b8e2f18c0f43fce".into(),
                data_hash_hex: "f6d9697880017989043d2fe0acc08d73411d891654ed6808b2346014613193b0".into(),
                witness_for_hex: "0000000000000000000000000000000000000000000000000000000000000000".into(),
                source_hash_hex: "0000000000000000000000000000000000000000000000000000000000000000".into(),
                source_type: 1,
                confidence: 8000,
                witnessing_depth: 5,
                attestor_relationship: 1,
                signer_asserted_at: 1780000100,
                retention_hint: -1,
                nonce_hex: "1111111111111111111111111111111111111111111111111111111111111111".into(),
            },
            "0202020202020202020202020202020202020202020202020202020202020202",
        ),
        (
            "peer_witnessed_physical",
            "Peer-witnessed contribution with physical observation. source_type = \
             peer_witnessed (9), witnessing_depth = physically_observed (1), \
             attestor_relationship = peer (3). source_hash is SHA-256 of a peer \
             pubkey (a distinct 32-byte pattern in this vector).",
            InputFields {
                signer_hex: "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1".into(),
                subject_hex: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into(),
                activity_hash_hex: "9f5ca22351d5f96bd639ce7e54489e5c8f234ae7cf6183ce8ea1a7728e27e175".into(),
                data_hash_hex: "957d0dbc210e888638accf23df93aff47f305389af7e9086a8f88579ce76bd9e".into(),
                witness_for_hex: "0000000000000000000000000000000000000000000000000000000000000000".into(),
                source_hash_hex: "4d12332c7f14cdaafa2b617b50feec749250000a8d75662c72c8931374176fca".into(),
                source_type: 9,
                confidence: 10000,
                witnessing_depth: 1,
                attestor_relationship: 3,
                signer_asserted_at: 1780000200,
                retention_hint: -1,
                nonce_hex: "3333333333333333333333333333333333333333333333333333333333333333".into(),
            },
            "0303030303030303030303030303030303030303030303030303030303030303",
        ),
        (
            "witness_for_endorsement",
            "Corroboration attestation where signer endorses another party's claim. \
             witness_for names the endorsed party's signer pubkey (nonzero). \
             source_type = coordinator_confirmed (8), attestor_relationship = \
             coordinator (2). Exercises the witness_for pointer field.",
            InputFields {
                signer_hex: "ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c".into(),
                subject_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                activity_hash_hex: "c3d3f9e4b0e1a6c5c7f2b19e1a2d3d4e5f60712834556677889aabbccddeeff0".into(),
                data_hash_hex: "1122334455667788112233445566778811223344556677881122334455667788".into(),
                witness_for_hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                source_hash_hex: "9a8b7c6d5e4f30219a8b7c6d5e4f30219a8b7c6d5e4f30219a8b7c6d5e4f3021".into(),
                source_type: 8,
                confidence: 9000,
                witnessing_depth: 3,
                attestor_relationship: 2,
                signer_asserted_at: 1780000300,
                retention_hint: 1811536300,
                nonce_hex: "5555555555555555555555555555555555555555555555555555555555555555".into(),
            },
            "0404040404040404040404040404040404040404040404040404040404040404",
        ),
        (
            "oauth_github_default_retention",
            "OAuth-authenticated attestation via GitHub. source_type = \
             oauth_authenticated (15). retention_hint = 0 (implementation \
             default). attestor_relationship = institution (6): the signer is \
             an ingestion pipeline attesting on behalf of a platform. Exercises \
             the zero-retention-hint sentinel and the highest registered \
             source_type value.",
            InputFields {
                signer_hex: "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1".into(),
                subject_hex: "7788770077887700778877007788770077887700778877007788770077887700".into(),
                activity_hash_hex: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
                data_hash_hex: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(),
                witness_for_hex: "0000000000000000000000000000000000000000000000000000000000000000".into(),
                source_hash_hex: "e1f2a3b4c5d6e7f8091a2b3c4d5e6f7081920a1b2c3d4e5f6071829304151617".into(),
                source_type: 15,
                confidence: 7500,
                witnessing_depth: 4,
                attestor_relationship: 6,
                signer_asserted_at: 1780000400,
                retention_hint: 0,
                nonce_hex: "6767676767676767676767676767676767676767676767676767676767676767".into(),
            },
            "0505050505050505050505050505050505050505050505050505050505050505",
        ),
        (
            "revocation_of_vector_1",
            "Additive revocation attestation per SPEC §4.3. activity_type = \
             https://sworn.dev/v1/revocation (activity_hash precomputed as \
             SHA-256(NFC(uri))). subject = SHA-256(canonical bytes of vector 1, \
             orcid_authorship_happy_path), naming the target attestation being \
             revoked. Signer is vector 1's signer (only the original signer can \
             revoke, per SPEC §4.3). data_hash is SHA-256 of the RFC 8785 \
             canonicalization of {\"reason\":\"test revocation for golden vector\"}. \
             source_type = self_reported (1) and source_hash = 32 zero bytes: \
             revocations are the signer's own act, no external source. \
             witnessing_depth = unspecified (0) and attestor_relationship = \
             unknown (0): SPEC §9.3 and §9.4 (as amended in v0.2.1) forbid the \
             self_asserted / self values when signer != subject, and here \
             subject is a hash of another attestation, not a party. Exercises \
             the additive-revocation pattern and the sourceless rule under a \
             non-self subject.",
            InputFields {
                signer_hex: "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c".into(),
                subject_hex: "00fbbd6a9272620fa3a6773e824dea0cb4afd759c37d4416b2ca0b21b2187657".into(),
                activity_hash_hex: "f44c48e055d5585fdb8c5fce0df8a8810dad3268987c3cdc5f31cdd89a937c01".into(),
                data_hash_hex: "23e6ae0ef3443c6b5fe2152a0a12539d79aa1b0f3790959637836ba90b4e2923".into(),
                witness_for_hex: "0000000000000000000000000000000000000000000000000000000000000000".into(),
                source_hash_hex: "0000000000000000000000000000000000000000000000000000000000000000".into(),
                source_type: 1,
                confidence: 10000,
                witnessing_depth: 0,
                attestor_relationship: 0,
                signer_asserted_at: 1780000500,
                retention_hint: -1,
                nonce_hex: "6969696969696969696969696969696969696969696969696969696969696969".into(),
            },
            "0101010101010101010101010101010101010101010101010101010101010101",
        ),
    ]
}

/// Emit a v0.2 vector file, computing expected canonical bytes and signature
/// deterministically from the baked inputs.
///
/// This is what a spec maintainer runs when the byte layout changes. The
/// resulting file is the source of truth for cross-implementation conformance.
pub fn emit_vectors() -> Result<VectorFile> {
    let baked = baked_vectors();
    let mut vectors = Vec::with_capacity(baked.len());

    for (name, notes, input, seed_hex) in baked {
        let fields = fields_from_inputs(&input)
            .with_context(|| format!("vector {name}: decode inputs"))?;
        let canonical = fields.to_bytes();

        let seed = decode_32(seed_hex, "signer_secret_seed_hex")?;
        let sk = SigningKey::from_bytes(&seed);

        // Sanity: derived pubkey MUST match the signer_hex declared in inputs.
        // A mismatch would indicate a hand-edited vector with inconsistent
        // seed/signer, which the runner would catch later but is cheaper to
        // catch here at emit time.
        let derived_pubkey_hex = hex::encode(sk.verifying_key().as_bytes());
        if derived_pubkey_hex != input.signer_hex {
            anyhow::bail!(
                "vector {name}: signer_hex ({}) does not match pubkey derived from seed ({})",
                input.signer_hex,
                derived_pubkey_hex
            );
        }

        let sig: Signature = sk.sign(&canonical);

        vectors.push(Vector {
            name: name.into(),
            notes: notes.into(),
            spec_version: SPEC_VERSION_V02,
            input_fields: input,
            signer_secret_seed_hex: seed_hex.into(),
            expected_canonical_bytes_hex: hex::encode(canonical),
            expected_canonical_bytes_len: CANONICAL_LEN,
            expected_signature_hex: hex::encode(sig.to_bytes()),
        });
    }

    Ok(VectorFile {
        spec_version: SPEC_VERSION_V02,
        spec_version_name: "v0.2".into(),
        canonical_bytes_length: CANONICAL_LEN,
        signature_algorithm: "Ed25519 PureEdDSA (RFC 8032)".into(),
        purpose: "Reference test vectors per SPEC §10.4. Any conforming implementation \
                  MUST reproduce expected_canonical_bytes_hex and expected_signature_hex \
                  byte-for-byte given the same input_fields and signer_secret_seed_hex."
            .into(),
        vectors,
    })
}

/// Write a `VectorFile` to disk as pretty-printed JSON.
pub fn write_vectors(vectors: &VectorFile, out: &Path) -> Result<()> {
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
    }
    let json = serde_json::to_string_pretty(vectors)?;
    fs::write(out, json).with_context(|| format!("write {}", out.display()))?;
    Ok(())
}

// ─── Verify ─────────────────────────────────────────────────────────

/// Per-vector conformance report.
#[derive(Debug)]
pub struct VectorReport {
    pub name: String,
    pub canonical_bytes_ok: bool,
    pub signature_ok: bool,
    pub verify_ok: bool,
    pub errors: Vec<String>,
}

impl VectorReport {
    pub fn passed(&self) -> bool {
        self.canonical_bytes_ok && self.signature_ok && self.verify_ok && self.errors.is_empty()
    }
}

/// Read a vector file and check each vector against three properties:
///
///   1. Reconstructed canonical bytes match `expected_canonical_bytes_hex`.
///   2. Ed25519 signature over reconstructed bytes matches `expected_signature_hex`.
///   3. Signature verifies against reconstructed bytes (transcription sanity check).
///
/// Returns per-vector reports. Overall pass status is `all(passed)`.
pub fn verify_vectors(path: &Path) -> Result<(VectorFile, Vec<VectorReport>)> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read vector file {}", path.display()))?;
    let file: VectorFile = serde_json::from_str(&raw)
        .with_context(|| format!("parse {} as vectors.json", path.display()))?;

    if file.canonical_bytes_length != CANONICAL_LEN {
        anyhow::bail!(
            "vector file declares canonical_bytes_length = {}; runner requires {}",
            file.canonical_bytes_length,
            CANONICAL_LEN
        );
    }

    let mut reports = Vec::with_capacity(file.vectors.len());
    for v in &file.vectors {
        reports.push(verify_one(v));
    }

    Ok((file, reports))
}

fn verify_one(v: &Vector) -> VectorReport {
    let mut report = VectorReport {
        name: v.name.clone(),
        canonical_bytes_ok: false,
        signature_ok: false,
        verify_ok: false,
        errors: Vec::new(),
    };

    // Reconstruct canonical bytes.
    let fields = match fields_from_inputs_with_version(&v.input_fields, v.spec_version) {
        Ok(f) => f,
        Err(e) => {
            report.errors.push(format!("field decode: {e}"));
            return report;
        }
    };
    let canonical = fields.to_bytes();

    // Check (1): canonical bytes match.
    match hex::decode(&v.expected_canonical_bytes_hex) {
        Ok(expected) if expected == canonical => {
            report.canonical_bytes_ok = true;
        }
        Ok(expected) => {
            report.errors.push(format!(
                "canonical bytes mismatch: expected {} bytes ({}...), got {} bytes ({}...)",
                expected.len(),
                hex::encode(&expected[..8.min(expected.len())]),
                canonical.len(),
                hex::encode(&canonical[..8]),
            ));
        }
        Err(e) => {
            report.errors.push(format!("expected canonical hex decode: {e}"));
        }
    }

    // Sign with the declared secret seed.
    let seed = match decode_32(&v.signer_secret_seed_hex, "signer_secret_seed_hex") {
        Ok(s) => s,
        Err(e) => {
            report.errors.push(e.to_string());
            return report;
        }
    };
    let sk = SigningKey::from_bytes(&seed);
    let sig: Signature = sk.sign(&canonical);

    // Check (2): signature matches.
    match hex::decode(&v.expected_signature_hex) {
        Ok(expected) if expected == sig.to_bytes().as_slice() => {
            report.signature_ok = true;
        }
        Ok(_) => {
            report
                .errors
                .push("signature mismatch: reproduce-sign path diverges from expected".into());
        }
        Err(e) => {
            report.errors.push(format!("expected signature hex decode: {e}"));
        }
    }

    // Check (3): verify signature against reconstructed bytes.
    let vk = sk.verifying_key();
    match vk.verify(&canonical, &sig) {
        Ok(()) => report.verify_ok = true,
        Err(e) => {
            report.errors.push(format!("signature verify: {e}"));
        }
    }

    // Extra sanity: signer_hex in inputs matches the pubkey derived from the seed.
    // A mismatch means the vector file is internally inconsistent; the checks
    // above may still pass because signature is over canonical bytes (which
    // include signer_hex from inputs, not the derived pubkey).
    let derived_pubkey_hex = hex::encode(vk.as_bytes());
    if derived_pubkey_hex != v.input_fields.signer_hex {
        report.errors.push(format!(
            "signer_hex/seed inconsistency: input signer_hex = {}, seed derives pubkey = {}",
            v.input_fields.signer_hex, derived_pubkey_hex
        ));
    }

    report
}

// ─── Helpers ────────────────────────────────────────────────────────

fn fields_from_inputs(input: &InputFields) -> Result<CanonicalFields> {
    fields_from_inputs_with_version(input, SPEC_VERSION_V02)
}

fn fields_from_inputs_with_version(input: &InputFields, spec_version: u16) -> Result<CanonicalFields> {
    // SPEC §2.4 sourceless rule enforced here for symmetry with `attest sign`.
    let source_hash = decode_32(&input.source_hash_hex, "source_hash_hex")?;
    if (input.source_type == 0 || input.source_type == 1) && source_hash != [0u8; 32] {
        anyhow::bail!(
            "SPEC §2.4: source_type {} is sourceless; source_hash MUST be 32 zero bytes",
            input.source_type
        );
    }
    if input.confidence > 10000 {
        anyhow::bail!("confidence {} exceeds max 10000 basis points", input.confidence);
    }

    Ok(CanonicalFields {
        spec_version,
        signer: decode_32(&input.signer_hex, "signer_hex")?,
        subject: decode_32(&input.subject_hex, "subject_hex")?,
        activity_hash: decode_32(&input.activity_hash_hex, "activity_hash_hex")?,
        data_hash: decode_32(&input.data_hash_hex, "data_hash_hex")?,
        witness_for: decode_32(&input.witness_for_hex, "witness_for_hex")?,
        source_hash,
        source_type: input.source_type,
        confidence: input.confidence,
        witnessing_depth: input.witnessing_depth,
        attestor_relationship: input.attestor_relationship,
        signer_asserted_at: input.signer_asserted_at,
        retention_hint: input.retention_hint,
        nonce: decode_32(&input.nonce_hex, "nonce_hex")?,
    })
}

fn decode_32(s: &str, field: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).with_context(|| format!("{field}: hex decode"))?;
    if bytes.len() != 32 {
        anyhow::bail!("{field}: expected 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Silences unused-import warning until Layer 5 wants sha256 here.
#[allow(dead_code)]
fn _sha256_placeholder(b: &[u8]) -> [u8; 32] {
    sha256(b)
}

// Suppress unused import warning for VerifyingKey; used implicitly via sk.verifying_key().
#[allow(dead_code)]
fn _vk_placeholder(k: [u8; 32]) -> Option<VerifyingKey> {
    VerifyingKey::from_bytes(&k).ok()
}

// ─── Unit tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_produces_six_vectors_with_declared_spec_version_v3() {
        let file = emit_vectors().unwrap();
        assert_eq!(file.spec_version, SPEC_VERSION_V02);
        assert_eq!(file.vectors.len(), 6);
        for v in &file.vectors {
            assert_eq!(v.spec_version, SPEC_VERSION_V02);
            assert_eq!(v.expected_canonical_bytes_len, CANONICAL_LEN);
        }
    }

    #[test]
    fn emit_self_verifies() {
        // What we emit MUST pass what we verify. Otherwise the two code paths
        // have diverged and the shipped fixtures will fail conformance.
        let file = emit_vectors().unwrap();
        for v in &file.vectors {
            let report = verify_one(v);
            assert!(
                report.passed(),
                "vector {} failed self-verify: {:?}",
                v.name,
                report.errors
            );
        }
    }

    #[test]
    fn spec_version_bytes_are_03_00_at_start() {
        // SPEC §3.1 fixes spec_version at bytes 0..2 as u16 little-endian.
        // v0.2 spec_version = 3, so the first two bytes are 03 00.
        let file = emit_vectors().unwrap();
        for v in &file.vectors {
            let bytes = hex::decode(&v.expected_canonical_bytes_hex).unwrap();
            assert_eq!(&bytes[0..2], &[0x03, 0x00], "vector {}", v.name);
        }
    }
}
