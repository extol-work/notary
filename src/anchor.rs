//! Layer 4: notarize an attestation to Solana Attestation Service.
//!
//! Three operations live here:
//!
//! - [`anchor`]: submit `CreateAttestation` (SAS discriminator = 6) with the
//!   46-byte v0.2 data section as payload. Idempotent: SAS's own
//!   account-already-exists check plus the deterministic PDA seed
//!   (`SHA-256(canonical_bytes)`) means re-anchoring the same attestation to
//!   the same cluster is a no-op.
//! - [`check`]: fetch the SAS account for a specific cluster, verify the owner
//!   is the SAS program, decode the 46-byte data section, and compare
//!   `spec_version + attestation_hash + signer_asserted_at` to the on-disk
//!   attestation.
//! - Reanchoring is not a distinct on-chain operation; it is [`anchor`] with a
//!   different cluster. The signed canonical bytes and signature are unchanged;
//!   only a new SAS PDA is created on the new substrate.
//!
//! ## Multi-anchor discipline: one file per anchor
//!
//! An attestation may be anchored to any number of substrates over its
//! lifetime. Each successful [`anchor`] call writes a sibling file next to
//! the attestation named `<stem>.anchor-<cluster>.json` (see [`AnchorFile`]).
//! The attestation.json itself is never mutated after `attest sign` produces
//! it: it is a signed artifact, and signed artifacts stay immutable.
//!
//! Multiple anchors on the same attestation live as multiple sibling files
//! (`foo.anchor-devnet.json`, `foo.anchor-mainnet-beta.json`). Nothing is
//! ever removed; each anchor file is append-only in effect. This matches §5
//! semantics: notarization is a durable commitment, not a revocable link.
//!
//! For backward compatibility with attestation.json files produced before the
//! two-file split, [`discover_anchors`] also reads legacy embedded anchors
//! (via `Attestation::legacy_anchors`) as if they were sibling files. Old
//! bundles verify and check without any migration on the user's part.
//!
//! ## SAS attestation account layout
//!
//! Per `program/src/processor/create_attestation.rs`, once created the SAS
//! attestation account has this layout:
//!
//! ```text
//!   offset   0.. 1   discriminator            (1 byte)
//!   offset   1..33   nonce                    (32 bytes = SHA-256(canonical_bytes))
//!   offset  33..65   credential pubkey        (32 bytes)
//!   offset  65..97   schema pubkey            (32 bytes)
//!   offset  97..101  data length prefix       (u32 LE, always 46 for v0.2)
//!   offset 101..147  data section             (46 bytes, v0.2 receipt encoded)
//!   offset 147..179  signer pubkey            (32 bytes = credential authority)
//!   offset 179..187  expiry                   (i64 LE, 0 = never)
//!   offset 187..219  token account            (32 bytes, zero for non-tokenized)
//! ```
//!
//! Total: 219 bytes. `check` reads the account, validates offset 33..97 match
//! the target credential and schema, then walks the data section per
//! [`sas::attestation_data_offset`](crate::sas::attestation_data_offset).

#![allow(dead_code)] // wired into main.rs; some helpers used only by anchor/check

use crate::attestation::Attestation;
use crate::devnet;
use crate::provision;
use crate::sas::{
    self, discriminator, find_attestation_pda, NOTARY_V2_ATTESTATION_HASH_LEN,
    NOTARY_V2_DATA_SECTION_WIRE_LEN, NOTARY_V2_SIGNER_ASSERTED_AT_LEN, NOTARY_V2_SPEC_VERSION_LEN,
    SAS_PROGRAM_ID,
};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signer as SolanaSigner;
use solana_sdk::transaction::Transaction;
#[allow(deprecated)]
use solana_sdk::system_program;
use std::str::FromStr;

/// SAS attestation account layout offsets (see module docstring).
mod account_offset {
    pub const DISCRIMINATOR: usize = 0;
    pub const NONCE: usize = 1;
    pub const CREDENTIAL: usize = 33;
    pub const SCHEMA: usize = 65;
    pub const DATA_LEN_PREFIX: usize = 97;
    pub const DATA: usize = 101;
    pub const SIGNER: usize = 147;
    pub const EXPIRY: usize = 179;
    pub const TOKEN_ACCOUNT: usize = 187;
    pub const TOTAL: usize = 219;
}

/// Which Solana cluster to anchor to.
///
/// The CLI defaults to Devnet. Mainnet-beta requires an explicit
/// `--cluster mainnet-beta` and a mainnet-provisioned credential + schema
/// (which do not exist as of this build; see `docs/devnet-setup.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cluster {
    Devnet,
    MainnetBeta,
}

impl Cluster {
    /// Parse the CLI string form.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "devnet" => Ok(Cluster::Devnet),
            "mainnet-beta" | "mainnet" => Ok(Cluster::MainnetBeta),
            other => anyhow::bail!(
                "unknown cluster {other:?}. Expected \"devnet\" or \"mainnet-beta\"."
            ),
        }
    }

    /// String representation as recorded in the anchor record.
    pub fn as_str(&self) -> &'static str {
        match self {
            Cluster::Devnet => "devnet",
            Cluster::MainnetBeta => "mainnet-beta",
        }
    }

    /// RPC endpoint for this cluster.
    pub fn rpc_url(&self) -> &'static str {
        match self {
            Cluster::Devnet => devnet::DEVNET_RPC,
            Cluster::MainnetBeta => "https://api.mainnet-beta.solana.com",
        }
    }

    /// True if this cluster is a testing environment (attestations here are
    /// not durable in a product sense; the `beta` flag on the anchor record
    /// captures the same idea).
    pub fn is_beta(&self) -> bool {
        matches!(self, Cluster::Devnet)
    }
}

/// A single on-chain notarization record.
///
/// Multiple records may exist per attestation (re-anchoring). Records are
/// append-only; each represents a durable commitment on a specific substrate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorRecord {
    /// Cluster identifier: `"devnet"`, `"mainnet-beta"`.
    pub cluster: String,

    /// SAS credential PDA (base58).
    pub credential: String,

    /// SAS schema PDA (base58).
    pub schema: String,

    /// SAS attestation PDA (base58). Deterministic: derived from
    /// `SHA-256(canonical_bytes)` per bindings/sas.md §3.
    pub attestation_pda: String,

    /// Transaction signature that created the anchor (base58).
    pub tx_signature: String,

    /// Solana slot at which the anchor was finalized.
    pub anchored_at_slot: u64,

    /// Substrate-authoritative timestamp per SPEC §2.7: Unix seconds of the
    /// Solana block that finalized the anchor tx. This is the trust-relevant
    /// time for downstream verifiers, not `signer_asserted_at`.
    pub anchored_at_block_time: i64,

    /// True if this cluster is a beta environment (devnet). Bundle consumers
    /// use this to flag attestations that are not production-durable.
    pub beta: bool,
}

/// Options passed to [`anchor`].
pub struct AnchorOpts {
    pub cluster: Cluster,
    /// Override the default credential PDA for this cluster.
    pub credential: Option<Pubkey>,
    /// Override the default schema PDA for this cluster.
    pub schema: Option<Pubkey>,
}

/// Result returned by [`anchor`].
pub enum AnchorOutcome {
    /// New anchor created on-chain.
    Anchored(AnchorRecord),
    /// Attestation was already anchored to this cluster (idempotent no-op).
    AlreadyAnchored(AnchorRecord),
}

/// Notarize `att` to `opts.cluster` under the specified credential + schema,
/// paying tx fees + rent from `fee_payer`.
///
/// Idempotent at the substrate level: the SAS PDA seed is
/// `SHA-256(canonical_bytes)`, so re-anchoring the same attestation to the
/// same cluster derives the same PDA. If the caller passes `existing`
/// pointing at a prior anchor record AND the on-chain account still exists,
/// returns [`AnchorOutcome::AlreadyAnchored`] with either the caller-provided
/// record or a synthesized one from on-chain state. Otherwise submits
/// `CreateAttestation` and returns [`AnchorOutcome::Anchored`].
///
/// The `existing` argument lets `cmd_anchor` pass in the record found in the
/// sibling `<stem>.anchor-<cluster>.json` file (if one is present). The
/// function itself is stateless with respect to file layout.
pub fn anchor(
    att: &Attestation,
    fee_payer: &devnet::LoadedKeypair,
    opts: AnchorOpts,
    existing: Option<&AnchorRecord>,
) -> anyhow::Result<AnchorOutcome> {
    // Resolve credential and schema. Defaults are the reference deployment
    // for devnet; mainnet has no defaults in this build and requires overrides.
    let (credential, schema) = resolve_credential_and_schema(&opts)?;

    // Compute the attestation PDA from the on-disk canonical bytes.
    let canonical = att
        .to_canonical_fields()
        .context("reconstruct canonical fields from attestation.json")?;
    let attestation_hash = canonical.attestation_hash();
    let (attestation_pda, _bump) =
        find_attestation_pda(&credential, &schema, &attestation_hash);

    let rpc = RpcClient::new_with_commitment(
        opts.cluster.rpc_url().to_string(),
        CommitmentConfig::confirmed(),
    );

    // Idempotency: SAS's PDA seed is deterministic (SHA-256(canonical_bytes)),
    // so if the PDA already exists on-chain the anchor operation has already
    // happened. Prefer the caller-provided `existing` record when available;
    // otherwise synthesize one from on-chain state.
    let _ = att; // reserved for future use (e.g., cross-checking on-chain data)
    if let Ok(account) = rpc.get_account(&attestation_pda) {
        if account.owner == SAS_PROGRAM_ID {
            if let Some(rec) = existing {
                // If the caller-passed record's PDA matches, return it verbatim
                // so the caller's tx signature and block time carry forward.
                if rec.attestation_pda == attestation_pda.to_string() {
                    return Ok(AnchorOutcome::AlreadyAnchored(rec.clone()));
                }
            }
            // No caller-provided record, or the caller's record referenced a
            // different PDA (unusual; would indicate their sibling file is
            // stale). Synthesize a record from on-chain state so the caller
            // can persist an accurate sibling file.
            let rec = AnchorRecord {
                cluster: opts.cluster.as_str().to_string(),
                credential: credential.to_string(),
                schema: schema.to_string(),
                attestation_pda: attestation_pda.to_string(),
                tx_signature: String::new(), // unknown; historical anchor
                anchored_at_slot: 0,          // unknown; historical anchor
                anchored_at_block_time: 0,    // unknown; historical anchor
                beta: opts.cluster.is_beta(),
            };
            return Ok(AnchorOutcome::AlreadyAnchored(rec));
        }
    }

    // Build CreateAttestation. SAS enforces:
    //   - authorized_signer must be in the credential's authorized_signers list.
    //     For the reference deployment, that is the credential authority itself.
    //   - expiry must be > current unix time or exactly 0 (never expires).
    //     We use 0 because notarization is durable per §5.
    let expiry_never: i64 = 0;
    let data = provision::encode_notary_v2_data(
        att.spec_version,
        &attestation_hash,
        att.signer_asserted_at,
    );

    let ix = create_attestation_ix(
        &fee_payer.sdk_keypair.pubkey(),
        &fee_payer.sdk_keypair.pubkey(),
        &credential,
        &schema,
        &attestation_pda,
        &attestation_hash,
        &data,
        expiry_never,
    );

    let recent_blockhash = rpc
        .get_latest_blockhash()
        .context("get_latest_blockhash")?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&fee_payer.sdk_keypair.pubkey()),
        &[&fee_payer.sdk_keypair],
        recent_blockhash,
    );
    let sig = rpc
        .send_and_confirm_transaction_with_spinner(&tx)
        .context("send create_attestation tx")?;

    // Fetch block time so downstream verifiers have the substrate-authoritative
    // timestamp. Failures here are non-fatal: the anchor succeeded, we just
    // record 0 as the block time and note it in the record.
    let (slot, block_time) = fetch_slot_and_block_time(&rpc, &sig.to_string())
        .unwrap_or((0, 0));

    let rec = AnchorRecord {
        cluster: opts.cluster.as_str().to_string(),
        credential: credential.to_string(),
        schema: schema.to_string(),
        attestation_pda: attestation_pda.to_string(),
        tx_signature: sig.to_string(),
        anchored_at_slot: slot,
        anchored_at_block_time: block_time,
        beta: opts.cluster.is_beta(),
    };
    Ok(AnchorOutcome::Anchored(rec))
}

/// Result of a check against a specific anchor record.
pub struct CheckResult {
    pub cluster: String,
    pub attestation_pda: String,
    pub on_chain_spec_version: u16,
    pub on_chain_attestation_hash: [u8; 32],
    pub on_chain_signer_asserted_at: i64,
    pub matches_local: bool,
    /// Populated only when the on-chain data does not match the local record.
    pub diagnostics: Vec<String>,
}

/// Fetch the SAS attestation account for `record.attestation_pda` on
/// `record.cluster`, decode the 46-byte data section, and compare
/// `spec_version + attestation_hash + signer_asserted_at` to `expected`.
///
/// The check requires only the local attestation record; it does not require
/// the payload or the signer's private key. Any third party can call this
/// against a bundle they were handed.
pub fn check(record: &AnchorRecord, expected: &Attestation) -> anyhow::Result<CheckResult> {
    let cluster = Cluster::parse(&record.cluster)?;
    let attestation_pda = Pubkey::from_str(&record.attestation_pda)
        .context("parse attestation_pda as base58")?;
    let credential = Pubkey::from_str(&record.credential)
        .context("parse credential as base58")?;
    let schema = Pubkey::from_str(&record.schema)
        .context("parse schema as base58")?;

    let rpc = RpcClient::new_with_commitment(
        cluster.rpc_url().to_string(),
        CommitmentConfig::confirmed(),
    );

    let account = rpc
        .get_account(&attestation_pda)
        .with_context(|| format!("fetch SAS attestation account {attestation_pda}"))?;

    if account.owner != SAS_PROGRAM_ID {
        anyhow::bail!(
            "account {attestation_pda} is owned by {} (expected SAS {SAS_PROGRAM_ID})",
            account.owner
        );
    }

    if account.data.len() < account_offset::TOTAL {
        anyhow::bail!(
            "account {attestation_pda} is {} bytes; expected at least {} for a SAS attestation",
            account.data.len(),
            account_offset::TOTAL
        );
    }

    let mut diagnostics = Vec::new();
    let mut matches_local = true;

    // Cross-check the credential and schema fields embedded in the account
    // against the record; a mismatch means the record's PDA doesn't actually
    // belong to the stated credential/schema, which would indicate a bundle
    // that has been tampered with or produced by a buggy implementation.
    let on_chain_credential: [u8; 32] = account.data
        [account_offset::CREDENTIAL..account_offset::CREDENTIAL + 32]
        .try_into()
        .expect("32-byte slice");
    if Pubkey::new_from_array(on_chain_credential) != credential {
        matches_local = false;
        diagnostics.push(format!(
            "on-chain credential {} does not match record credential {credential}",
            Pubkey::new_from_array(on_chain_credential)
        ));
    }
    let on_chain_schema: [u8; 32] = account.data
        [account_offset::SCHEMA..account_offset::SCHEMA + 32]
        .try_into()
        .expect("32-byte slice");
    if Pubkey::new_from_array(on_chain_schema) != schema {
        matches_local = false;
        diagnostics.push(format!(
            "on-chain schema {} does not match record schema {schema}",
            Pubkey::new_from_array(on_chain_schema)
        ));
    }

    // Confirm the on-chain data-length prefix matches the v0.2 receipt wire size.
    let data_len = u32::from_le_bytes(
        account.data[account_offset::DATA_LEN_PREFIX..account_offset::DATA_LEN_PREFIX + 4]
            .try_into()
            .expect("4-byte slice"),
    ) as usize;
    if data_len != NOTARY_V2_DATA_SECTION_WIRE_LEN {
        anyhow::bail!(
            "SAS data section is {data_len} bytes; expected {} for v0.2 receipt",
            NOTARY_V2_DATA_SECTION_WIRE_LEN
        );
    }

    // Walk the 46-byte data section.
    let data = &account.data[account_offset::DATA..account_offset::DATA + data_len];
    let on_chain_spec_version = u16::from_le_bytes(
        data[sas::attestation_data_offset::SPEC_VERSION
            ..sas::attestation_data_offset::SPEC_VERSION + NOTARY_V2_SPEC_VERSION_LEN]
            .try_into()
            .expect("2-byte slice"),
    );
    let hash_len_prefix = u32::from_le_bytes(
        data[sas::attestation_data_offset::ATTESTATION_HASH_LEN
            ..sas::attestation_data_offset::ATTESTATION_HASH_LEN + 4]
            .try_into()
            .expect("4-byte slice"),
    ) as usize;
    if hash_len_prefix != NOTARY_V2_ATTESTATION_HASH_LEN {
        anyhow::bail!(
            "attestation_hash length prefix is {hash_len_prefix}; expected {}",
            NOTARY_V2_ATTESTATION_HASH_LEN
        );
    }
    let on_chain_attestation_hash: [u8; 32] = data[sas::attestation_data_offset::ATTESTATION_HASH
        ..sas::attestation_data_offset::ATTESTATION_HASH + NOTARY_V2_ATTESTATION_HASH_LEN]
        .try_into()
        .expect("32-byte slice");
    let on_chain_signer_asserted_at = i64::from_le_bytes(
        data[sas::attestation_data_offset::SIGNER_ASSERTED_AT
            ..sas::attestation_data_offset::SIGNER_ASSERTED_AT + NOTARY_V2_SIGNER_ASSERTED_AT_LEN]
            .try_into()
            .expect("8-byte slice"),
    );

    // Compare to the local attestation.
    let local_canonical = expected
        .to_canonical_fields()
        .context("reconstruct canonical fields for check comparison")?;
    let local_hash = local_canonical.attestation_hash();

    if on_chain_spec_version != expected.spec_version {
        matches_local = false;
        diagnostics.push(format!(
            "on-chain spec_version {on_chain_spec_version} != local {}",
            expected.spec_version
        ));
    }
    if on_chain_attestation_hash != local_hash {
        matches_local = false;
        diagnostics.push(format!(
            "on-chain attestation_hash {} != local {}",
            hex::encode(on_chain_attestation_hash),
            hex::encode(local_hash)
        ));
    }
    if on_chain_signer_asserted_at != expected.signer_asserted_at {
        matches_local = false;
        diagnostics.push(format!(
            "on-chain signer_asserted_at {on_chain_signer_asserted_at} != local {}",
            expected.signer_asserted_at
        ));
    }

    Ok(CheckResult {
        cluster: record.cluster.clone(),
        attestation_pda: record.attestation_pda.clone(),
        on_chain_spec_version,
        on_chain_attestation_hash,
        on_chain_signer_asserted_at,
        matches_local,
        diagnostics,
    })
}

// ─── Internals ───────────────────────────────────────────────────────

/// Build the SAS `CreateAttestation` instruction.
///
/// Accounts (per `program/src/processor/create_attestation.rs`):
///   0. payer (signer, writable)
///   1. authorized_signer (signer, read-only) must be in credential.signers
///   2. credential (read-only, SAS-owned)
///   3. schema (read-only, SAS-owned)
///   4. attestation PDA (writable, empty, owned by system before creation)
///   5. system program
///
/// Data: `[6] || nonce (32) || data_len (u32 LE) || data || expiry (i64 LE)`
fn create_attestation_ix(
    payer: &Pubkey,
    authorized_signer: &Pubkey,
    credential: &Pubkey,
    schema: &Pubkey,
    attestation_pda: &Pubkey,
    nonce: &[u8; 32],
    data: &[u8],
    expiry: i64,
) -> Instruction {
    let mut ix_data = Vec::with_capacity(1 + 32 + 4 + data.len() + 8);
    ix_data.push(discriminator::CREATE_ATTESTATION);
    ix_data.extend_from_slice(nonce);
    ix_data.extend_from_slice(&(data.len() as u32).to_le_bytes());
    ix_data.extend_from_slice(data);
    ix_data.extend_from_slice(&expiry.to_le_bytes());

    Instruction {
        program_id: SAS_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new_readonly(*authorized_signer, true),
            AccountMeta::new_readonly(*credential, false),
            AccountMeta::new_readonly(*schema, false),
            AccountMeta::new(*attestation_pda, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: ix_data,
    }
}

fn resolve_credential_and_schema(opts: &AnchorOpts) -> anyhow::Result<(Pubkey, Pubkey)> {
    let credential = match opts.credential {
        Some(pk) => pk,
        None => match opts.cluster {
            Cluster::Devnet => Pubkey::from_str(sas::devnet_reference::CREDENTIAL)
                .expect("baked devnet credential parses"),
            Cluster::MainnetBeta => anyhow::bail!(
                "no mainnet credential is baked into this build. \
                 Provide --credential explicitly, or provision one first."
            ),
        },
    };
    let schema = match opts.schema {
        Some(pk) => pk,
        None => match opts.cluster {
            Cluster::Devnet => Pubkey::from_str(sas::devnet_reference::SCHEMA)
                .expect("baked devnet schema parses"),
            Cluster::MainnetBeta => anyhow::bail!(
                "no mainnet schema is baked into this build. \
                 Provide --schema explicitly, or provision one first."
            ),
        },
    };
    Ok((credential, schema))
}

// ─── File-layout helpers (sibling anchor files) ─────────────────────
//
// Anchors live in files named `<attestation-stem>.anchor-<cluster>.json` next
// to the attestation itself. Each file is self-identifying: it carries the
// `attestation_hash` (SHA-256 of the canonical bytes) so a reader can confirm
// the anchor covers the attestation they think it does before doing any RPC.
//
// Discovery (`discover_anchors`) unions three sources:
//   1. Sibling `<stem>.anchor-*.json` files in the same directory
//   2. Legacy embedded `Attestation.legacy_anchors` (pre-refactor bundles)
//
// Duplicates (same cluster in both a sibling file and legacy_anchors) prefer
// the sibling file, since that is the current authoritative shape.

/// Self-identifying anchor record: an [`AnchorRecord`] plus the SHA-256 of
/// the canonical bytes it covers. Written by `attest anchor` as a sibling
/// file, read by `attest check` and `attest confirm`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorFile {
    /// SHA-256 of the attestation's canonical bytes (lowercase hex). Lets a
    /// reader confirm which attestation this anchor covers without doing an
    /// RPC call.
    pub attestation_hash: String,

    /// The anchor record itself, flattened into the same JSON object.
    #[serde(flatten)]
    pub record: AnchorRecord,
}

/// Compute the sibling anchor file path for `(attestation_path, cluster)`.
///
/// `foo.json` + `devnet` → `foo.anchor-devnet.json`
/// `attestation.json` + `mainnet-beta` → `attestation.anchor-mainnet-beta.json`
pub fn anchor_file_path(attestation_path: &std::path::Path, cluster: &Cluster) -> std::path::PathBuf {
    let stem = attestation_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("attestation");
    let parent = attestation_path.parent().unwrap_or_else(|| std::path::Path::new(""));
    parent.join(format!("{stem}.anchor-{}.json", cluster.as_str()))
}

/// Write an anchor file next to the attestation.
///
/// Refuses to overwrite an existing file: an anchor operation that succeeded
/// once should not silently blast over a prior record. Callers who want to
/// re-anchor an existing cluster should delete the sibling file explicitly.
pub fn write_anchor_file(
    path: &std::path::Path,
    attestation_hash: &[u8; 32],
    record: &AnchorRecord,
) -> anyhow::Result<()> {
    if path.exists() {
        anyhow::bail!(
            "refusing to overwrite existing anchor file {}. \
             Delete it explicitly if you intend to replace it.",
            path.display()
        );
    }
    let file = AnchorFile {
        attestation_hash: hex::encode(attestation_hash),
        record: record.clone(),
    };
    let json = serde_json::to_string_pretty(&file)?;
    std::fs::write(path, json.as_bytes())
        .with_context(|| format!("write anchor file {}", path.display()))?;
    Ok(())
}

/// Read an anchor file. Returns the full [`AnchorFile`] including the
/// self-identifying `attestation_hash`.
pub fn read_anchor_file(path: &std::path::Path) -> anyhow::Result<AnchorFile> {
    let json = std::fs::read_to_string(path)
        .with_context(|| format!("read anchor file {}", path.display()))?;
    let file: AnchorFile = serde_json::from_str(&json)
        .with_context(|| format!("parse {} as anchor file JSON", path.display()))?;
    Ok(file)
}

/// A discovered anchor, plus where it came from (for error messages).
#[derive(Debug, Clone)]
pub struct DiscoveredAnchor {
    /// Human-readable source: either a sibling file path, or the string
    /// `"legacy embedded in attestation.json"`.
    pub source: String,
    pub record: AnchorRecord,
}

/// Discover all anchors associated with an attestation.
///
/// Unions two sources:
///   1. Sibling files matching `<stem>.anchor-*.json` in the same directory
///      as `attestation_path`.
///   2. `Attestation.legacy_anchors` (embedded in the attestation.json for
///      pre-refactor bundles).
///
/// Sibling files also carry an `attestation_hash` field that is cross-checked
/// against the attestation's actual hash: if a sibling file's declared hash
/// does not match, the file is skipped and a warning is emitted. This defends
/// against a mixed-up bundle where the wrong anchor file was dropped next to
/// an attestation.
pub fn discover_anchors(
    attestation_path: &std::path::Path,
    att: &Attestation,
) -> anyhow::Result<Vec<DiscoveredAnchor>> {
    let expected_hash = att
        .to_canonical_fields()
        .context("reconstruct canonical fields for anchor discovery")?
        .attestation_hash();
    let expected_hash_hex = hex::encode(expected_hash);

    let mut out: Vec<DiscoveredAnchor> = Vec::new();
    let mut seen_clusters: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Source 1: sibling files.
    let stem = attestation_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("attestation");
    let dir = attestation_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""));

    // Only list dir if it exists. In-memory tests may pass paths that don't.
    let dir_to_read: &std::path::Path = if dir.as_os_str().is_empty() {
        std::path::Path::new(".")
    } else {
        dir
    };
    if dir_to_read.exists() {
        let entries = std::fs::read_dir(dir_to_read)
            .with_context(|| format!("list directory {}", dir_to_read.display()))?;
        let prefix = format!("{stem}.anchor-");
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = match name.to_str() {
                Some(s) => s,
                None => continue,
            };
            if !name_str.starts_with(&prefix) || !name_str.ends_with(".json") {
                continue;
            }
            let file = match read_anchor_file(&entry.path()) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!(
                        "warning: skipping unreadable anchor file {}: {e}",
                        entry.path().display()
                    );
                    continue;
                }
            };
            if file.attestation_hash != expected_hash_hex {
                eprintln!(
                    "warning: skipping {}: declares attestation_hash {} but attestation's hash is {}",
                    entry.path().display(),
                    file.attestation_hash,
                    expected_hash_hex
                );
                continue;
            }
            seen_clusters.insert(file.record.cluster.clone());
            out.push(DiscoveredAnchor {
                source: entry.path().display().to_string(),
                record: file.record,
            });
        }
    }

    // Source 2: legacy embedded anchors. Skip any cluster already found in a
    // sibling file (sibling wins, since it's the current canonical shape).
    for rec in &att.legacy_anchors {
        if seen_clusters.contains(&rec.cluster) {
            continue;
        }
        out.push(DiscoveredAnchor {
            source: "legacy embedded in attestation.json".to_string(),
            record: rec.clone(),
        });
    }

    // Deterministic ordering by cluster for stable output.
    out.sort_by(|a, b| a.record.cluster.cmp(&b.record.cluster));
    Ok(out)
}

fn fetch_slot_and_block_time(rpc: &RpcClient, sig_str: &str) -> anyhow::Result<(u64, i64)> {
    use solana_sdk::signature::Signature;
    let sig = Signature::from_str(sig_str).context("parse tx signature as base58")?;
    // get_signature_statuses returns the confirmation status of a set of
    // signatures. The included slot is what we want for anchored_at_slot.
    let statuses = rpc
        .get_signature_statuses(&[sig])
        .context("get_signature_statuses")?;
    let status = statuses
        .value
        .into_iter()
        .next()
        .flatten()
        .ok_or_else(|| anyhow::anyhow!("no status returned for {sig_str}"))?;
    let slot = status.slot;
    let block_time = rpc
        .get_block_time(slot)
        .context("get_block_time")?;
    Ok((slot, block_time))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_parse_accepts_expected_forms() {
        assert_eq!(Cluster::parse("devnet").unwrap(), Cluster::Devnet);
        assert_eq!(
            Cluster::parse("mainnet-beta").unwrap(),
            Cluster::MainnetBeta
        );
        assert_eq!(Cluster::parse("mainnet").unwrap(), Cluster::MainnetBeta);
        assert!(Cluster::parse("localnet").is_err());
    }

    #[test]
    fn cluster_beta_flag_is_true_for_devnet_only() {
        assert!(Cluster::Devnet.is_beta());
        assert!(!Cluster::MainnetBeta.is_beta());
    }

    #[test]
    fn create_attestation_ix_shape() {
        let payer = Pubkey::new_from_array([1u8; 32]);
        let credential = Pubkey::new_from_array([2u8; 32]);
        let schema = Pubkey::new_from_array([3u8; 32]);
        let pda = Pubkey::new_from_array([4u8; 32]);
        let nonce = [0xAAu8; 32];
        let data = [0xBBu8; NOTARY_V2_DATA_SECTION_WIRE_LEN];

        let ix = create_attestation_ix(&payer, &payer, &credential, &schema, &pda, &nonce, &data, 0);

        assert_eq!(ix.data[0], 6, "CreateAttestation discriminator");
        assert_eq!(&ix.data[1..33], &nonce, "nonce inline");
        assert_eq!(
            u32::from_le_bytes(ix.data[33..37].try_into().unwrap()) as usize,
            NOTARY_V2_DATA_SECTION_WIRE_LEN,
            "data length prefix"
        );
        assert_eq!(&ix.data[37..37 + NOTARY_V2_DATA_SECTION_WIRE_LEN], &data);
        let expiry_off = 37 + NOTARY_V2_DATA_SECTION_WIRE_LEN;
        assert_eq!(&ix.data[expiry_off..expiry_off + 8], &0i64.to_le_bytes());
        assert_eq!(ix.accounts.len(), 6);
    }

    #[test]
    fn anchor_file_path_uses_stem_dot_anchor_dash_cluster_dot_json() {
        use std::path::PathBuf;
        let att = PathBuf::from("/tmp/foo/attestation.json");
        let path = anchor_file_path(&att, &Cluster::Devnet);
        assert_eq!(path.to_str().unwrap(), "/tmp/foo/attestation.anchor-devnet.json");

        let att = PathBuf::from("bar.json");
        let path = anchor_file_path(&att, &Cluster::MainnetBeta);
        assert_eq!(path.to_str().unwrap(), "bar.anchor-mainnet-beta.json");
    }

    #[test]
    fn anchor_file_roundtrips_and_carries_attestation_hash() {
        use std::path::PathBuf;
        let mut path = std::env::temp_dir();
        path.push(format!(
            "notary-anchor-file-{}.anchor-devnet.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let record = AnchorRecord {
            cluster: "devnet".into(),
            credential: "Cred111111111111111111111111111111111111111".into(),
            schema: "Schm11111111111111111111111111111111111111".into(),
            attestation_pda: "Att111111111111111111111111111111111111111".into(),
            tx_signature: "Tx11111111111111111111111111111111111111111".into(),
            anchored_at_slot: 42,
            anchored_at_block_time: 1_780_000_000,
            beta: true,
        };
        let hash = [0xAAu8; 32];

        write_anchor_file(&path, &hash, &record).expect("write");
        let file = read_anchor_file(&path).expect("read");

        assert_eq!(file.attestation_hash, hex::encode(hash));
        assert_eq!(file.record, record);

        // Refuses to overwrite.
        let err = write_anchor_file(&path, &hash, &record).expect_err("second write must refuse");
        assert!(err.to_string().contains("refusing to overwrite"));

        let _ = std::fs::remove_file(&path);
        let _: PathBuf = path;
    }

    #[test]
    fn discover_anchors_reads_sibling_files_and_falls_back_to_legacy() {
        // Build a minimal Attestation with a known signer_hex etc., write it
        // to a tempdir, drop one sibling anchor file, and set one legacy
        // embedded anchor for a different cluster. Discovery should return
        // both, with the sibling for its cluster preferred over any legacy
        // record that happens to also cover it.
        use std::fs;
        let tmpdir = std::env::temp_dir().join(format!(
            "notary-discover-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&tmpdir);
        fs::create_dir_all(&tmpdir).expect("mkdir");
        let att_path = tmpdir.join("bundle.json");

        // Minimal legal attestation. Values are placeholders; discovery only
        // needs the canonical hash, and legacy_anchors get read verbatim.
        let att = Attestation {
            spec_version: crate::canonical::SPEC_VERSION_V02,
            signer: hex::encode([1u8; 32]),
            subject: hex::encode([2u8; 32]),
            activity_type: "https://example.org/x/v1".into(),
            data_hash: hex::encode([3u8; 32]),
            witness_for: hex::encode([0u8; 32]),
            source_hash: hex::encode([0u8; 32]),
            source_type: 1,
            confidence: 10000,
            witnessing_depth: 0,
            attestor_relationship: 0,
            signer_asserted_at: 1_780_000_000,
            retention_hint: 0,
            nonce: hex::encode([4u8; 32]),
            signature: hex::encode([5u8; 64]),
            payload: None,
            legacy_anchors: vec![AnchorRecord {
                cluster: "mainnet-beta".into(),
                credential: "C-legacy".into(),
                schema: "S-legacy".into(),
                attestation_pda: "P-legacy".into(),
                tx_signature: "T-legacy".into(),
                anchored_at_slot: 0,
                anchored_at_block_time: 0,
                beta: false,
            }],
        };
        // Write attestation.json so its path is real (discover_anchors uses
        // the directory of the path to list siblings).
        fs::write(&att_path, serde_json::to_string_pretty(&att).unwrap()).expect("write att");

        // Write one sibling file for devnet with the CORRECT attestation hash.
        let hash = att.to_canonical_fields().unwrap().attestation_hash();
        let sibling_path = anchor_file_path(&att_path, &Cluster::Devnet);
        let sibling_record = AnchorRecord {
            cluster: "devnet".into(),
            credential: "C-sib".into(),
            schema: "S-sib".into(),
            attestation_pda: "P-sib".into(),
            tx_signature: "T-sib".into(),
            anchored_at_slot: 100,
            anchored_at_block_time: 1_780_000_100,
            beta: true,
        };
        write_anchor_file(&sibling_path, &hash, &sibling_record).expect("write sibling");

        // Discover: should find both.
        let discovered = discover_anchors(&att_path, &att).expect("discover");
        assert_eq!(discovered.len(), 2, "sibling + legacy");
        let clusters: Vec<&str> = discovered.iter().map(|d| d.record.cluster.as_str()).collect();
        assert!(clusters.contains(&"devnet"));
        assert!(clusters.contains(&"mainnet-beta"));

        // Sibling record wins for its own cluster (source contains the path).
        let dv = discovered.iter().find(|d| d.record.cluster == "devnet").unwrap();
        assert!(dv.source.contains("bundle.anchor-devnet.json"));
        assert_eq!(dv.record.credential, "C-sib");

        // Legacy record shows up with the informative source label.
        let mb = discovered
            .iter()
            .find(|d| d.record.cluster == "mainnet-beta")
            .unwrap();
        assert_eq!(mb.source, "legacy embedded in attestation.json");
        assert_eq!(mb.record.credential, "C-legacy");

        let _ = fs::remove_dir_all(&tmpdir);
    }

    #[test]
    fn account_offsets_are_stable() {
        // If any of these drift, `check` would silently read the wrong bytes.
        assert_eq!(account_offset::NONCE, 1);
        assert_eq!(account_offset::CREDENTIAL, 33);
        assert_eq!(account_offset::SCHEMA, 65);
        assert_eq!(account_offset::DATA_LEN_PREFIX, 97);
        assert_eq!(account_offset::DATA, 101);
        assert_eq!(account_offset::DATA + NOTARY_V2_DATA_SECTION_WIRE_LEN, 147);
        assert_eq!(account_offset::SIGNER, 147);
        assert_eq!(account_offset::EXPIRY, 179);
        assert_eq!(account_offset::TOKEN_ACCOUNT, 187);
        assert_eq!(account_offset::TOTAL, 219);
    }
}
