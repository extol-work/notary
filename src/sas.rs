//! Solana Attestation Service (SAS) binding per
//! [bindings/sas.md](https://github.com/extol-work/sworn/blob/main/bindings/sas.md).
//!
//! This module carries only static constants and pure PDA-derivation helpers.
//! Network code (RPC calls, transaction submission, credential provisioning)
//! lives in `src/anchor.rs` and lands with the `attest anchor` command in the
//! next commit.
//!
//! ## What SAS looks like at the byte level
//!
//! SAS is built on Pinocchio (not Anchor) and uses single-byte instruction
//! discriminators (not Anchor's 8-byte sighash). The instruction encoding is
//! Shank-generated; see the constants in `discriminator` below.
//!
//! ## PDA seeds
//!
//! Three PDAs matter for a conforming notary deployment:
//!
//! - **Credential.** `["credential", authority, credential_name]`. Created once
//!   per environment (devnet / mainnet). The authority is the party that can
//!   add or remove authorized signers.
//! - **Schema.** `["schema", credential, schema_name, [version]]`. Created
//!   once per environment under a credential. For conforming ANS deployments,
//!   the schema data section is exactly 42 bytes:
//!   `spec_version (2 bytes) || attestation_hash (32 bytes) || signer_asserted_at (8 bytes)`.
//! - **Attestation.** `["attestation", credential, schema, nonce]`. Created
//!   per attestation. The nonce is `SHA-256(canonical_bytes)`, which is
//!   identical to the attestation_hash. This is opaque with respect to
//!   signer, subject, activity_type, and every other identifying field.
//!
//! The final property is what enforces the ANS §5.1 non-walkability
//! discipline at the substrate level: a `getProgramAccounts` scan by
//! `[b"attestation", credential, schema, *]` returns a list of opaque hashes,
//! not a walkable directory of who signed what about whom.

// Many items in this module are used by the anchor/check/reanchor commands
// that land in the next commit. Allowing dead_code at module scope keeps the
// intermediate build quiet without hiding legitimate warnings elsewhere.
#![allow(dead_code)]

use solana_sdk::pubkey::Pubkey;

/// SAS program ID on both mainnet-beta and devnet. Sourced from
/// [bindings/sas.md §2](https://github.com/extol-work/sworn/blob/main/bindings/sas.md#2-sas-program-id)
/// and verified against the running mainnet SAS deployment. The 32-byte
/// literal is used rather than `Pubkey::from_str` so this is a compile-time
/// constant with no possibility of decode failure at runtime.
///
/// Base58: `22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG`
pub const SAS_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    15, 94, 158, 213, 55, 30, 44, 112, 137, 140, 169, 253, 14, 119, 192, 6,
    92, 171, 93, 160, 46, 86, 103, 139, 39, 19, 56, 42, 243, 116, 89, 183,
]);

/// PDA seeds for SAS accounts.
pub mod seed {
    pub const CREDENTIAL: &[u8] = b"credential";
    pub const SCHEMA: &[u8] = b"schema";
    pub const ATTESTATION: &[u8] = b"attestation";
    /// SAS emits program-level events under this authority PDA; required as an
    /// account for a handful of SAS instructions. Derived from
    /// `[b"__event_authority"]` under the SAS program.
    pub const EVENT_AUTHORITY: &[u8] = b"__event_authority";
}

/// SAS instruction discriminators. Single byte per Pinocchio convention.
///
/// These values match the Shank-generated ordering in the SAS program source
/// and are stable across mainnet and devnet deployments. Do not reorder or
/// renumber; any change would break every existing SAS attestation.
pub mod discriminator {
    pub const CREATE_CREDENTIAL: u8 = 0;
    pub const CHANGE_AUTHORIZED_SIGNERS: u8 = 3;
    pub const CREATE_SCHEMA: u8 = 4;
    pub const CREATE_ATTESTATION: u8 = 6;
    pub const CLOSE_ATTESTATION: u8 = 7;
}

/// SAS account data section length for a conforming ANS attestation.
///
/// Per bindings/sas.md §5: `spec_version || attestation_hash || signer_asserted_at`
/// = 2 + 32 + 8 = 42 bytes exactly. Nothing else. Any additional field turns
/// into a searchable memcmp target and violates the non-walkability discipline
/// of ANS §5.1.
pub const NOTARY_SCHEMA_DATA_LEN: usize = 42;

/// Byte offsets inside the 42-byte notary attestation data section.
pub mod attestation_data_offset {
    pub const SPEC_VERSION: usize = 0; // u16 LE, 2 bytes
    pub const ATTESTATION_HASH: usize = 2; // 32 bytes (SHA-256 of canonical bytes)
    pub const SIGNER_ASSERTED_AT: usize = 34; // i64 LE, 8 bytes
                                              // 34 + 8 = 42
}

/// Encode the 42-byte SAS attestation data section per bindings/sas.md §5.
///
/// Layout:
/// ```text
/// spec_version         (2 bytes, u16 LE)
/// attestation_hash     (32 bytes, SHA-256 of canonical bytes)
/// signer_asserted_at   (8 bytes, i64 LE, Unix seconds)
/// ```
pub fn encode_notary_data(
    spec_version: u16,
    attestation_hash: &[u8; 32],
    signer_asserted_at: i64,
) -> [u8; NOTARY_SCHEMA_DATA_LEN] {
    let mut out = [0u8; NOTARY_SCHEMA_DATA_LEN];
    out[attestation_data_offset::SPEC_VERSION..attestation_data_offset::SPEC_VERSION + 2]
        .copy_from_slice(&spec_version.to_le_bytes());
    out[attestation_data_offset::ATTESTATION_HASH..attestation_data_offset::ATTESTATION_HASH + 32]
        .copy_from_slice(attestation_hash);
    out[attestation_data_offset::SIGNER_ASSERTED_AT
        ..attestation_data_offset::SIGNER_ASSERTED_AT + 8]
        .copy_from_slice(&signer_asserted_at.to_le_bytes());
    out
}

/// Derive the SAS Credential PDA.
///
/// Seeds: `["credential", authority, credential_name]`. The `credential_name`
/// is a short UTF-8 byte string identifying the deployment
/// (e.g., `b"notary-cli-devnet"` for this CLI's devnet deployment).
pub fn find_credential_pda(authority: &Pubkey, name: &[u8]) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[seed::CREDENTIAL, authority.as_ref(), name],
        &SAS_PROGRAM_ID,
    )
}

/// Derive the SAS Schema PDA.
///
/// Seeds: `["schema", credential, schema_name, [version]]`. The schema
/// version byte lets the same credential carry multiple schema iterations;
/// v0.2 conformant deployments use version = 1.
pub fn find_schema_pda(credential: &Pubkey, name: &[u8], version: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[seed::SCHEMA, credential.as_ref(), name, &[version]],
        &SAS_PROGRAM_ID,
    )
}

/// Derive the SAS Attestation PDA per bindings/sas.md §3.
///
/// Seeds: `["attestation", credential, schema, nonce]` where
/// `nonce = SHA-256(canonical_bytes)`. The nonce is opaque with respect to
/// every identifying field of the attestation; this is the property that
/// enforces the ANS §5.1 non-walkability discipline at the substrate level.
///
/// The PDA is idempotent: two calls to notarize the same canonical bytes
/// derive the same PDA, so SAS's account-already-exists check prevents
/// duplicates without any CLI-side state.
pub fn find_attestation_pda(
    credential: &Pubkey,
    schema: &Pubkey,
    nonce: &[u8; 32],
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            seed::ATTESTATION,
            credential.as_ref(),
            schema.as_ref(),
            nonce.as_ref(),
        ],
        &SAS_PROGRAM_ID,
    )
}

/// Derive the SAS event authority PDA.
///
/// Seeds: `["__event_authority"]`. Required as an account for
/// `CloseAttestation` and similar SAS instructions that emit program-level
/// events. Not needed for `CreateAttestation`.
pub fn find_event_authority_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[seed::EVENT_AUTHORITY], &SAS_PROGRAM_ID)
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sas_program_id_matches_base58_literal() {
        // If either the byte literal or the base58 representation drifts,
        // this test surfaces it before any RPC call would silently fail.
        let expected = "22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG";
        assert_eq!(SAS_PROGRAM_ID.to_string(), expected);
    }

    #[test]
    fn notary_data_section_is_exactly_42_bytes() {
        // ANS §5.1 non-walkability discipline: 42 bytes, no more, no less.
        // Any drift here (padding, extra field, alignment) would break
        // cross-implementation substrate reads.
        assert_eq!(NOTARY_SCHEMA_DATA_LEN, 42);
        let data = encode_notary_data(3, &[0xAB; 32], 1_780_000_000);
        assert_eq!(data.len(), 42);
    }

    #[test]
    fn notary_data_layout_puts_fields_at_expected_offsets() {
        let spec_version: u16 = 3;
        let attestation_hash = [0x77u8; 32];
        let signer_asserted_at: i64 = 1_780_000_000;
        let data = encode_notary_data(spec_version, &attestation_hash, signer_asserted_at);

        // spec_version: bytes 0..2 little-endian
        assert_eq!(&data[0..2], &spec_version.to_le_bytes());
        // attestation_hash: bytes 2..34
        assert_eq!(&data[2..34], &attestation_hash);
        // signer_asserted_at: bytes 34..42 little-endian
        assert_eq!(&data[34..42], &signer_asserted_at.to_le_bytes());
    }

    #[test]
    fn pda_derivation_is_deterministic() {
        // The seed schemas are the whole point of the non-walkability
        // discipline. If any of these accidentally change, the CLI would
        // produce PDAs that no other conforming implementation could find.
        let authority = Pubkey::new_from_array([1u8; 32]);
        let (cred_a, bump_a) = find_credential_pda(&authority, b"notary-cli-devnet");
        let (cred_b, bump_b) = find_credential_pda(&authority, b"notary-cli-devnet");
        assert_eq!(cred_a, cred_b);
        assert_eq!(bump_a, bump_b);

        let (schema_a, _) = find_schema_pda(&cred_a, b"ans-v2-notary", 1);
        let (schema_b, _) = find_schema_pda(&cred_a, b"ans-v2-notary", 1);
        assert_eq!(schema_a, schema_b);

        let nonce = [0xEEu8; 32];
        let (att_a, _) = find_attestation_pda(&cred_a, &schema_a, &nonce);
        let (att_b, _) = find_attestation_pda(&cred_a, &schema_a, &nonce);
        assert_eq!(att_a, att_b);
    }

    #[test]
    fn attestation_pda_changes_when_nonce_changes() {
        // Sanity: two different nonces produce two different PDAs. If not,
        // the seed function is broken and every attestation would collide.
        let authority = Pubkey::new_from_array([1u8; 32]);
        let (cred, _) = find_credential_pda(&authority, b"notary-cli-devnet");
        let (schema, _) = find_schema_pda(&cred, b"ans-v2-notary", 1);

        let (att_a, _) = find_attestation_pda(&cred, &schema, &[0xAAu8; 32]);
        let (att_b, _) = find_attestation_pda(&cred, &schema, &[0xBBu8; 32]);
        assert_ne!(att_a, att_b);
    }
}
