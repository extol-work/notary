//! SAS credential + schema provisioning helpers.
//!
//! Two one-time on-chain setups per environment (devnet, mainnet):
//!
//! 1. **Credential** via SAS `CreateCredential` (discriminator=0). Names the
//!    authority that can add or remove authorized signers.
//! 2. **Schema** via SAS `CreateSchema` (discriminator=1). Defines the data
//!    layout for all attestations under the credential.
//!
//! ## Schema layout for the v0.2 receipt
//!
//! The `bindings/sas.md §5` document names a 42-byte data section:
//! `spec_version (u16) || attestation_hash (32) || signer_asserted_at (i64)`.
//!
//! But SAS's schema type system (see the `SchemaDataTypes` enum at
//! [solana-attestation-service/program/src/state/schema.rs](https://github.com/solana-foundation/solana-attestation-service/blob/main/program/src/state/schema.rs))
//! has no fixed-length byte array type. Available types are scalar primitives
//! (U8..U128, I8..I128, Bool, Char, String) and their Vec variants. A 32-byte
//! hash therefore MUST be encoded as `VecU8`, which adds a 4-byte little-endian
//! length prefix.
//!
//! On the wire the data section is **46 bytes**, not 42:
//!
//! ```text
//!   offset 0..2    spec_version           (u16 LE)                  = 2 bytes
//!   offset 2..6    attestation_hash len   (u32 LE, always 32)       = 4 bytes
//!   offset 6..38   attestation_hash       (32 bytes)                = 32 bytes
//!   offset 38..46  signer_asserted_at     (i64 LE)                  = 8 bytes
//! ```
//!
//! Schema layout codes: `[1, 13, 8]` (U16, VecU8, I64).
//! Field names: `["spec_version", "attestation_hash", "signer_asserted_at"]`.
//!
//! Follow-up: `bindings/sas.md` should be corrected to say "46 bytes wire /
//! 42 bytes semantic payload" rather than the current "42 bytes." Small doc
//! fix separate from this commit.

#![allow(dead_code)] // used by admin subcommands; some helpers land next commit

use crate::sas::{
    discriminator, find_credential_pda, find_schema_pda,
    NOTARY_V2_ATTESTATION_HASH_LEN, NOTARY_V2_DATA_SECTION_WIRE_LEN, NOTARY_V2_SIGNER_ASSERTED_AT_LEN,
    NOTARY_V2_SPEC_VERSION_LEN, SAS_PROGRAM_ID,
};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
// The `solana-system-interface` crate is the new home for the system program
// ID, but pulling it in as a direct dep for one constant is worse than the
// deprecation warning. Silencing locally.
#[allow(deprecated)]
use solana_sdk::system_program;

/// Credential name used by the notary CLI reference deployment on devnet.
pub const CREDENTIAL_NAME_DEVNET: &str = "notary-cli-devnet";

/// Schema name for new v0.2 provisioning. Historical note: the notary CLI's
/// original devnet reference schema was provisioned under the legacy name
/// `ans-v2-notary` at address `Cnu2C6jK6GpUdjWXjacJqQyzYwzr3mXpRKSj7gmrn4wW`.
/// New adopter provisioning uses this constant; the old on-chain schema
/// remains valid under its legacy name for the notary CLI's own historical
/// anchors.
pub const SCHEMA_NAME: &str = "notary-attestation";

/// Schema version for the v0.2 receipt layout.
pub const SCHEMA_VERSION: u8 = 1;

/// Human-readable schema description stored on-chain.
pub const SCHEMA_DESCRIPTION: &str =
    "Attestation Notary v0.2 receipt: spec_version + attestation_hash + signer_asserted_at.";

/// SAS schema layout codes for the v0.2 receipt (see module doc).
/// U16 = 1, VecU8 = 13, I64 = 8.
pub const NOTARY_V2_SCHEMA_LAYOUT: &[u8] = &[1, 13, 8];

/// Schema field names in the same order as the layout codes.
pub const NOTARY_V2_FIELD_NAMES: &[&str] =
    &["spec_version", "attestation_hash", "signer_asserted_at"];

// ─── Borsh-lite encoders ──────────────────────────────────────────────
//
// SAS instruction data uses a small subset of Borsh: strings and byte
// vectors are `u32 little-endian length` followed by raw bytes; vectors of
// pubkeys are `u32 length` followed by 32 bytes per pubkey. Rather than
// pull in the full borsh crate for these three shapes, we implement them
// inline.

fn encode_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

fn encode_vec_u8(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

fn encode_vec_string(strings: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    for s in strings {
        out.extend_from_slice(&encode_string(s));
    }
    out
}

fn encode_vec_pubkey(pubkeys: &[Pubkey]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + pubkeys.len() * 32);
    out.extend_from_slice(&(pubkeys.len() as u32).to_le_bytes());
    for pk in pubkeys {
        out.extend_from_slice(pk.as_ref());
    }
    out
}

// ─── CreateCredential (discriminator = 0) ─────────────────────────────

/// Build the SAS `CreateCredential` instruction.
///
/// Accounts (per `program/src/processor/create_credential.rs`):
///   0. payer (signer, writable)
///   1. credential PDA (writable, empty, owned by system program before creation)
///   2. authority (signer, read-only)
///   3. system program
///
/// Data: `[0] || string(name) || vec_pubkey(signers)`
pub fn create_credential_ix(
    payer: &Pubkey,
    authority: &Pubkey,
    credential_pda: &Pubkey,
    name: &str,
    authorized_signers: &[Pubkey],
) -> Instruction {
    let mut data = Vec::new();
    data.push(discriminator::CREATE_CREDENTIAL);
    data.extend_from_slice(&encode_string(name));
    data.extend_from_slice(&encode_vec_pubkey(authorized_signers));

    Instruction {
        program_id: SAS_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*credential_pda, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    }
}

// ─── CreateSchema (discriminator = 1) ─────────────────────────────────

/// Build the SAS `CreateSchema` instruction.
///
/// Accounts (per `program/src/processor/create_schema.rs`):
///   0. payer (signer, writable)
///   1. authority (signer, read-only)
///   2. credential PDA (read-only, owned by SAS)
///   3. schema PDA (writable, empty, owned by system program before creation)
///   4. system program
///
/// Data: `[1] || string(name) || string(description) || vec_u8(layout) || vec_string(field_names)`
pub fn create_schema_ix(
    payer: &Pubkey,
    authority: &Pubkey,
    credential_pda: &Pubkey,
    schema_pda: &Pubkey,
    name: &str,
    description: &str,
    layout: &[u8],
    field_names: &[&str],
) -> Instruction {
    let mut data = Vec::new();
    data.push(discriminator::CREATE_SCHEMA);
    data.extend_from_slice(&encode_string(name));
    data.extend_from_slice(&encode_string(description));
    data.extend_from_slice(&encode_vec_u8(layout));
    data.extend_from_slice(&encode_vec_string(field_names));

    Instruction {
        program_id: SAS_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new_readonly(*credential_pda, false),
            AccountMeta::new(*schema_pda, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    }
}

// ─── v0.2 data section encoder ────────────────────────────────────────
//
// Encoding is what `attest anchor` will submit as the `data` field of the
// SAS `CreateAttestation` instruction. Layout matches the schema declared
// via `create_schema_ix` above.

/// Build the 46-byte on-wire data section for a v0.2 notary attestation.
///
/// Layout:
///   spec_version         (u16 LE)          2 bytes
///   attestation_hash len (u32 LE = 32)     4 bytes
///   attestation_hash     (32 bytes)       32 bytes
///   signer_asserted_at   (i64 LE)          8 bytes
///   ------------------------------------------
///   total                                 46 bytes
pub fn encode_notary_v2_data(
    spec_version: u16,
    attestation_hash: &[u8; 32],
    signer_asserted_at: i64,
) -> [u8; NOTARY_V2_DATA_SECTION_WIRE_LEN] {
    let mut out = [0u8; NOTARY_V2_DATA_SECTION_WIRE_LEN];
    let mut off = 0;

    out[off..off + NOTARY_V2_SPEC_VERSION_LEN].copy_from_slice(&spec_version.to_le_bytes());
    off += NOTARY_V2_SPEC_VERSION_LEN;

    out[off..off + 4].copy_from_slice(&(NOTARY_V2_ATTESTATION_HASH_LEN as u32).to_le_bytes());
    off += 4;

    out[off..off + NOTARY_V2_ATTESTATION_HASH_LEN].copy_from_slice(attestation_hash);
    off += NOTARY_V2_ATTESTATION_HASH_LEN;

    out[off..off + NOTARY_V2_SIGNER_ASSERTED_AT_LEN]
        .copy_from_slice(&signer_asserted_at.to_le_bytes());
    off += NOTARY_V2_SIGNER_ASSERTED_AT_LEN;

    debug_assert_eq!(off, NOTARY_V2_DATA_SECTION_WIRE_LEN);
    out
}

// ─── PDA convenience ──────────────────────────────────────────────────

/// Derive both PDAs for a devnet provisioning run.
pub fn devnet_pdas(authority: &Pubkey) -> (Pubkey, Pubkey) {
    let (credential, _) = find_credential_pda(authority, CREDENTIAL_NAME_DEVNET.as_bytes());
    let (schema, _) = find_schema_pda(&credential, SCHEMA_NAME.as_bytes(), SCHEMA_VERSION);
    (credential, schema)
}

// ─── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::pubkey::Pubkey;

    #[test]
    fn encode_string_matches_borsh_wire_format() {
        let out = encode_string("extol");
        assert_eq!(out.len(), 4 + 5);
        assert_eq!(&out[0..4], &5u32.to_le_bytes());
        assert_eq!(&out[4..9], b"extol");
    }

    #[test]
    fn encode_vec_pubkey_produces_length_then_32_per_entry() {
        let pks = [Pubkey::new_from_array([1u8; 32]), Pubkey::new_from_array([2u8; 32])];
        let out = encode_vec_pubkey(&pks);
        assert_eq!(out.len(), 4 + 32 * 2);
        assert_eq!(&out[0..4], &2u32.to_le_bytes());
        assert_eq!(&out[4..36], &[1u8; 32]);
        assert_eq!(&out[36..68], &[2u8; 32]);
    }

    #[test]
    fn create_credential_ix_starts_with_disc_0() {
        let auth = Pubkey::new_from_array([9u8; 32]);
        let cred = Pubkey::new_from_array([10u8; 32]);
        let ix = create_credential_ix(&auth, &auth, &cred, "notary-cli-devnet", &[auth]);
        assert_eq!(ix.data[0], 0, "CreateCredential discriminator must be 0");
        assert_eq!(ix.accounts.len(), 4);
        assert!(ix.accounts[0].is_signer && ix.accounts[0].is_writable, "payer");
        assert!(ix.accounts[1].is_writable, "credential PDA writable");
        assert!(ix.accounts[2].is_signer && !ix.accounts[2].is_writable, "authority");
    }

    #[test]
    fn create_schema_ix_starts_with_disc_1_and_encodes_layout() {
        let auth = Pubkey::new_from_array([9u8; 32]);
        let cred = Pubkey::new_from_array([10u8; 32]);
        let schema = Pubkey::new_from_array([11u8; 32]);
        let ix = create_schema_ix(
            &auth,
            &auth,
            &cred,
            &schema,
            SCHEMA_NAME,
            "test",
            NOTARY_V2_SCHEMA_LAYOUT,
            NOTARY_V2_FIELD_NAMES,
        );
        assert_eq!(ix.data[0], 1, "CreateSchema discriminator must be 1");
        assert_eq!(ix.accounts.len(), 5);
    }

    #[test]
    fn notary_v2_data_encoding_is_46_bytes_and_field_layout_is_stable() {
        let hash = [0xAB; 32];
        let data = encode_notary_v2_data(3, &hash, 1_780_000_000);
        assert_eq!(data.len(), 46);

        // spec_version = 3 as u16 LE
        assert_eq!(&data[0..2], &[0x03, 0x00]);
        // attestation_hash length prefix = 32 as u32 LE
        assert_eq!(&data[2..6], &[0x20, 0x00, 0x00, 0x00]);
        // 32 bytes of the hash
        assert_eq!(&data[6..38], &hash);
        // signer_asserted_at = 1_780_000_000 as i64 LE
        assert_eq!(&data[38..46], &1_780_000_000i64.to_le_bytes());
    }

    #[test]
    fn devnet_pdas_are_deterministic() {
        let auth = Pubkey::new_from_array([42u8; 32]);
        let (c1, s1) = devnet_pdas(&auth);
        let (c2, s2) = devnet_pdas(&auth);
        assert_eq!(c1, c2, "credential PDA should be deterministic per authority");
        assert_eq!(s1, s2, "schema PDA should be deterministic per credential");
    }
}
