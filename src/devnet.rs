//! Devnet provisioning helpers for the notary CLI.
//!
//! This module carries the operator-facing setup commands:
//!
//! - `attest admin keygen-fee-payer` — generate a Solana devnet keypair that
//!   pays transaction fees and rent for provisioning + anchoring.
//! - `attest admin provision-credential` — create the SAS credential PDA (TBD).
//! - `attest admin provision-schema` — create the SAS schema PDA (TBD).
//!
//! The credential and schema provisioning commands land alongside `attest
//! anchor` once the fee-payer has been funded. This commit ships only the
//! keygen so the funding handshake with the operator can begin.
//!
//! ## Keypair file format
//!
//! Solana's standard keypair file is a JSON array of 64 u8 values:
//!
//!   `[<32-byte seed>, <32-byte pubkey>]`
//!
//! This is compatible with `solana-keygen`, `solana-cli`, and every wallet
//! that reads Solana keypair files. We write in this format so operators
//! can inspect the file with the standard tools if they want to.

use anyhow::Context;
use rand::rngs::OsRng;
use rand::RngCore;
use solana_sdk::signature::{Keypair, Signer};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Generate a fresh Solana keypair and write it to `path` in the standard
/// Solana JSON-array format. Refuses to overwrite an existing file (the
/// keypair is single-use in the sense that regenerating it would abandon
/// whatever devnet SOL is currently held at the old address).
///
/// Returns the base58-encoded public key so the caller can print it for the
/// operator to fund.
pub fn keygen_fee_payer(path: &Path) -> anyhow::Result<String> {
    if path.exists() {
        anyhow::bail!(
            "refusing to overwrite existing keypair at {}. \
             Delete or move it explicitly if you intend to replace it.",
            path.display()
        );
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create parent directory {}", parent.display()))?;
        }
    }

    // Generate 32 bytes of entropy via the OS RNG. This is what the standard
    // Solana keygen uses; we do not derive from a seed phrase because the
    // fee-payer key has no long-term value beyond devnet SOL custody.
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);

    // Convert seed to a Solana Keypair (which itself uses ed25519-dalek
    // internally). Keypair::from_bytes wants the full 64-byte expanded form
    // (seed || pubkey), so we derive the pubkey via ed25519_dalek and
    // concatenate.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();

    let mut solana_kp_bytes = [0u8; 64];
    solana_kp_bytes[..32].copy_from_slice(&seed);
    solana_kp_bytes[32..].copy_from_slice(&pubkey_bytes);

    // Confirm the Solana SDK deserializes it cleanly and derives the same
    // pubkey. Sanity-check against silent format drift; catches any future
    // Keypair::from_bytes change that would break our custom serializer.
    let sdk_kp = Keypair::try_from(&solana_kp_bytes[..])
        .map_err(|e| anyhow::anyhow!("solana-sdk rejected generated keypair bytes: {e}"))?;
    let sdk_pubkey_bytes = sdk_kp.pubkey().to_bytes();
    if sdk_pubkey_bytes != pubkey_bytes {
        anyhow::bail!(
            "solana-sdk pubkey ({}) does not match ed25519_dalek pubkey ({}). \
             This is a serialization bug; do not use this keypair.",
            hex::encode(sdk_pubkey_bytes),
            hex::encode(pubkey_bytes)
        );
    }

    // Serialize as JSON array of u8 (standard Solana keypair file format).
    let json_array: Vec<u8> = solana_kp_bytes.to_vec();
    let json = serde_json::to_string(&json_array)
        .map_err(|e| anyhow::anyhow!("serialize keypair as JSON array: {e}"))?;

    fs::write(path, json).with_context(|| format!("write keypair {}", path.display()))?;

    // Restrict permissions to owner-read-only. This is best-effort: if the
    // filesystem does not support Unix permissions the operation is silently
    // skipped, but on macOS/Linux (where operators run this CLI) it applies.
    let perms = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms)
        .with_context(|| format!("set permissions on {}", path.display()))?;

    let pubkey_base58 = bs58::encode(pubkey_bytes).into_string();
    Ok(pubkey_base58)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn keygen_writes_a_solana_compatible_keypair() {
        let mut path = env::temp_dir();
        path.push(format!("notary-devnet-kp-{}.json", std::process::id()));
        let _ = fs::remove_file(&path);

        let pubkey_base58 = keygen_fee_payer(&path).expect("keygen");
        assert_eq!(pubkey_base58.len(), 44, "Solana base58 pubkey is 43 or 44 chars");

        // Read back and confirm it's a 64-byte JSON array.
        let contents = fs::read_to_string(&path).expect("read");
        let arr: Vec<u8> = serde_json::from_str(&contents).expect("parse JSON array");
        assert_eq!(arr.len(), 64, "Solana keypair is 32-byte seed + 32-byte pubkey");

        // Confirm the Solana SDK reads it back with matching pubkey.
        let kp = Keypair::try_from(&arr[..]).expect("Keypair::try_from");
        let sdk_base58 = kp.pubkey().to_string();
        assert_eq!(sdk_base58, pubkey_base58, "SDK pubkey must match reported pubkey");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn keygen_refuses_to_overwrite() {
        let mut path = env::temp_dir();
        path.push(format!("notary-devnet-kp-noover-{}.json", std::process::id()));
        let _ = fs::remove_file(&path);

        keygen_fee_payer(&path).expect("first keygen");
        let err = keygen_fee_payer(&path).expect_err("second keygen should refuse");
        assert!(
            err.to_string().contains("refusing to overwrite"),
            "expected refusal, got: {err}"
        );

        let _ = fs::remove_file(&path);
    }
}
