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
//!   once per environment under a credential. For conforming deployments,
//!   the schema data section is exactly 42 bytes:
//!   `spec_version (2 bytes) || attestation_hash (32 bytes) || signer_asserted_at (8 bytes)`.
//! - **Attestation.** `["attestation", credential, schema, nonce]`. Created
//!   per attestation. The nonce is `SHA-256(canonical_bytes)`, which is
//!   identical to the attestation_hash. This is opaque with respect to
//!   signer, subject, activity_type, and every other identifying field.
//!
//! The final property is what enforces the §5.1 non-walkability
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

/// Reference deployment addresses on devnet.
///
/// Provisioned via `attest admin provision-credential` and
/// `attest admin provision-schema` on 2026-08-13 under fee-payer
/// `ySRnUCkb6FFgz6NThWdJbRbQJJdwb2uo4QMvG5TbSez`. These are the addresses
/// `attest anchor`, `attest check`, and `attest reanchor` default to on
/// devnet. Operators running their own deployment override via
/// `--credential` and `--schema` on those subcommands.
pub mod devnet_reference {
    /// SAS credential PDA: name = "notary-cli-devnet", authority = fee-payer above.
    pub const CREDENTIAL: &str = "2wp93cFgFeZANui2rbDbFFkCju1f8NaaBBa9uuXeKZQw";
    /// SAS schema PDA: legacy name = "ans-v2-notary", version = 1. The
    /// address stays valid on-chain; new provisioning uses the current
    /// `SCHEMA_NAME` in provision.rs (`notary-attestation`), which derives
    /// to a different PDA.
    ///
    /// Schema layout `[1, 13, 8]` (U16, VecU8, I64) corresponding to
    /// `spec_version || attestation_hash || signer_asserted_at`.
    pub const SCHEMA: &str = "Cnu2C6jK6GpUdjWXjacJqQyzYwzr3mXpRKSj7gmrn4wW";
}

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
///
/// Verified against SAS `program/src/instructions.rs`:
/// <https://github.com/solana-foundation/solana-attestation-service/blob/main/program/src/instructions.rs>
pub mod discriminator {
    pub const CREATE_CREDENTIAL: u8 = 0;
    pub const CREATE_SCHEMA: u8 = 1;
    pub const CHANGE_AUTHORIZED_SIGNERS: u8 = 3;
    pub const CREATE_ATTESTATION: u8 = 6;
    pub const CLOSE_ATTESTATION: u8 = 7;
}

/// SAS account data section length for a conforming Attestation Notary v0.2 record.
///
/// ## Wire layout: 46 bytes total, not 42
///
/// `bindings/sas.md §5` names the *semantic* payload as 42 bytes:
/// `spec_version (2) || attestation_hash (32) || signer_asserted_at (8)`.
///
/// SAS's schema type system (see the `SchemaDataTypes` enum at
/// [solana-attestation-service/program/src/state/schema.rs](https://github.com/solana-foundation/solana-attestation-service/blob/main/program/src/state/schema.rs))
/// has no fixed-length byte array type. A 32-byte hash MUST be encoded as
/// `VecU8`, which adds a 4-byte little-endian length prefix. On the wire:
///
/// ```text
///   offset  0.. 2   spec_version           (u16 LE)                = 2 bytes
///   offset  2.. 6   attestation_hash len   (u32 LE, always = 32)   = 4 bytes
///   offset  6..38   attestation_hash       (32 bytes)              = 32 bytes
///   offset 38..46   signer_asserted_at     (i64 LE)                = 8 bytes
/// ```
///
/// The extra 4 bytes do not change the non-walkability property (the PDA
/// seed is `SHA-256(canonical_bytes)`, opaque with respect to every field),
/// but they are visible in the on-chain account.
///
/// `bindings/sas.md §5` should be corrected to reflect the 46-byte wire size.
/// Follow-up doc fix; not blocking on-chain provisioning.
pub const NOTARY_V2_SPEC_VERSION_LEN: usize = 2;
pub const NOTARY_V2_ATTESTATION_HASH_LEN: usize = 32;
pub const NOTARY_V2_SIGNER_ASSERTED_AT_LEN: usize = 8;
pub const NOTARY_V2_DATA_SECTION_WIRE_LEN: usize =
    NOTARY_V2_SPEC_VERSION_LEN + 4 + NOTARY_V2_ATTESTATION_HASH_LEN + NOTARY_V2_SIGNER_ASSERTED_AT_LEN;

/// Byte offsets inside the 46-byte on-wire notary attestation data section.
pub mod attestation_data_offset {
    pub const SPEC_VERSION: usize = 0; // u16 LE, 2 bytes
    pub const ATTESTATION_HASH_LEN: usize = 2; // u32 LE prefix, always 32
    pub const ATTESTATION_HASH: usize = 6; // 32 bytes (SHA-256 of canonical bytes)
    pub const SIGNER_ASSERTED_AT: usize = 38; // i64 LE, 8 bytes
                                              // 38 + 8 = 46
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
/// enforces the §5.1 non-walkability discipline at the substrate level.
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
    fn notary_data_wire_len_is_46_bytes() {
        // SAS's VecU8 encoding forces a 4-byte length prefix on the 32-byte
        // hash. Semantic payload is 42 bytes; on-wire is 46. If either the
        // constant or the offset table drifts, this fires.
        assert_eq!(NOTARY_V2_DATA_SECTION_WIRE_LEN, 46);
        assert_eq!(
            attestation_data_offset::SIGNER_ASSERTED_AT + NOTARY_V2_SIGNER_ASSERTED_AT_LEN,
            46
        );
    }

    #[test]
    fn devnet_reference_addresses_match_baked_pdas() {
        // The reference addresses were provisioned under a specific fee-payer
        // authority. If either the SAS_PROGRAM_ID literal or the PDA seed
        // derivation drifts, the baked strings would no longer match, and
        // any anchor/check operation would silently target a wrong PDA.
        //
        // Guard: re-derive the PDAs from the known-fixed authority pubkey and
        // credential/schema names, then assert against the baked strings.
        use std::str::FromStr;

        let authority = Pubkey::from_str("ySRnUCkb6FFgz6NThWdJbRbQJJdwb2uo4QMvG5TbSez").unwrap();
        let (credential, _) = find_credential_pda(&authority, b"notary-cli-devnet");
        assert_eq!(
            credential.to_string(),
            devnet_reference::CREDENTIAL,
            "baked devnet CREDENTIAL address must equal what the seeds derive"
        );

        // The baked devnet SCHEMA was provisioned under the legacy schema
        // name `ans-v2-notary` before the `notary-attestation` rename.
        // Derivation here uses the historical literal on purpose; new
        // provisioning uses `provision::SCHEMA_NAME` and derives to a
        // different (unbaked) address.
        let (schema, _) = find_schema_pda(&credential, b"ans-v2-notary", 1);
        assert_eq!(
            schema.to_string(),
            devnet_reference::SCHEMA,
            "baked devnet SCHEMA address must equal what the legacy seeds derive"
        );
    }

    #[test]
    fn attestation_data_offsets_agree_with_layout_codes() {
        // Field ordering must match schema layout codes [1, 13, 8] and the
        // NOTARY_V2_FIELD_NAMES declaration in provision.rs. If a reordering
        // ever happens it would break every anchor + every reader.
        assert_eq!(attestation_data_offset::SPEC_VERSION, 0);
        assert_eq!(attestation_data_offset::ATTESTATION_HASH_LEN, 2);
        assert_eq!(attestation_data_offset::ATTESTATION_HASH, 6);
        assert_eq!(attestation_data_offset::SIGNER_ASSERTED_AT, 38);
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

        let (schema_a, _) = find_schema_pda(&cred_a, b"notary-attestation", 1);
        let (schema_b, _) = find_schema_pda(&cred_a, b"notary-attestation", 1);
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
        let (schema, _) = find_schema_pda(&cred, b"notary-attestation", 1);

        let (att_a, _) = find_attestation_pda(&cred, &schema, &[0xAAu8; 32]);
        let (att_b, _) = find_attestation_pda(&cred, &schema, &[0xBBu8; 32]);
        assert_ne!(att_a, att_b);
    }
}
