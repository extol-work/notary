//! Devnet provisioning helpers for the notary CLI.
//!
//! This module carries the operator-facing setup commands:
//!
//! - `attest admin keygen-fee-payer` generates a Solana devnet keypair that
//!   pays transaction fees and rent for provisioning + anchoring.
//! - `attest admin balance` queries the funded balance via devnet RPC.
//! - `attest admin provision-credential` creates the SAS credential PDA
//!   (idempotent).
//! - `attest admin provision-schema` creates the SAS schema PDA under the
//!   credential (idempotent).
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

/// Devnet RPC endpoint. Public, unmetered.
pub const DEVNET_RPC: &str = "https://api.devnet.solana.com";

/// A loaded Solana keypair plus derivation cache.
pub struct LoadedKeypair {
    pub sdk_keypair: Keypair,
    pub pubkey_bytes: [u8; 32],
}

impl LoadedKeypair {
    /// Base58-encoded public key.
    pub fn pubkey_base58(&self) -> String {
        bs58::encode(self.pubkey_bytes).into_string()
    }
}

/// Read a Solana JSON-array keypair file (as written by [`keygen_fee_payer`]
/// or `solana-keygen`) and return the loaded keypair.
///
/// Refuses to load a keypair whose stored pubkey does not match the pubkey
/// derived from the seed. This catches file corruption and defends against
/// a malicious edit that would substitute the pubkey while leaving the seed
/// intact.
pub fn load_keypair(path: &Path) -> anyhow::Result<LoadedKeypair> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read keypair {}", path.display()))?;
    let arr: Vec<u8> = serde_json::from_str(&contents)
        .with_context(|| format!("parse {} as Solana JSON-array keypair", path.display()))?;
    if arr.len() != 64 {
        anyhow::bail!(
            "keypair {} is {} bytes; expected 64 (32-byte seed + 32-byte pubkey)",
            path.display(),
            arr.len()
        );
    }

    let sdk_keypair = Keypair::try_from(&arr[..])
        .map_err(|e| anyhow::anyhow!("solana-sdk rejected keypair bytes: {e}"))?;
    let pubkey_bytes = sdk_keypair.pubkey().to_bytes();

    // Sanity-check: derive the pubkey from the seed via ed25519-dalek and
    // compare. If the stored pubkey has been tampered with, this fails loud.
    let seed: [u8; 32] = arr[..32].try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let derived = signing_key.verifying_key().to_bytes();
    if derived != pubkey_bytes {
        anyhow::bail!(
            "keypair {} is inconsistent: stored pubkey {} does not match seed-derived pubkey {}",
            path.display(),
            hex::encode(pubkey_bytes),
            hex::encode(derived)
        );
    }

    Ok(LoadedKeypair {
        sdk_keypair,
        pubkey_bytes,
    })
}

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
    fn load_keypair_round_trips_a_generated_keypair() {
        let mut path = env::temp_dir();
        path.push(format!("notary-devnet-kp-load-{}.json", std::process::id()));
        let _ = fs::remove_file(&path);

        let expected_pubkey = keygen_fee_payer(&path).expect("keygen");
        let loaded = load_keypair(&path).expect("load");
        assert_eq!(loaded.pubkey_base58(), expected_pubkey);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_keypair_rejects_tampered_pubkey() {
        let mut path = env::temp_dir();
        path.push(format!(
            "notary-devnet-kp-tamper-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        keygen_fee_payer(&path).expect("keygen");
        let contents = fs::read_to_string(&path).expect("read");
        let mut arr: Vec<u8> = serde_json::from_str(&contents).expect("parse");
        arr[63] ^= 0xFF; // flip a byte in the stored pubkey
        fs::write(&path, serde_json::to_string(&arr).unwrap()).expect("write");

        let result = load_keypair(&path);
        assert!(result.is_err(), "load must reject tampered pubkey");
        // Either error path is acceptable defense: solana-sdk's own signature
        // check often catches it first with "signature error", but our
        // ed25519-dalek cross-check is defense in depth.
        let err_msg = result.err().unwrap().to_string();
        let looks_like_rejection = err_msg.contains("inconsistent")
            || err_msg.contains("does not match")
            || err_msg.contains("solana-sdk rejected")
            || err_msg.contains("signature error");
        assert!(
            looks_like_rejection,
            "expected rejection of tampered pubkey, got: {err_msg}"
        );

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
