//! Ed25519 keyfile format: private-seed storage and load.
//!
//! Format is a small JSON object with the 32-byte private seed as lowercase
//! hex and the derived 32-byte public key as lowercase hex. The public key is
//! redundant with the seed but stored to catch corruption on load without
//! having to re-derive.
//!
//! This is a REFERENCE format. Production deployments should treat these
//! keyfiles as sensitive material and wrap with proper KMS or hardware keys.
//! Keyfile permissions are set to 0600 on save (unix); users must confirm.

use anyhow::Context;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// On-disk keyfile shape.
#[derive(Debug, Serialize, Deserialize)]
pub struct Keyfile {
    /// Format marker. Present so we can extend later without ambiguity.
    pub format: String,

    /// 32-byte Ed25519 seed, lowercase hex.
    pub private_seed: String,

    /// 32-byte Ed25519 public key, lowercase hex. Redundant with seed.
    pub public_key: String,
}

impl Keyfile {
    pub const FORMAT: &'static str = "notary-ed25519-keyfile-v1";

    /// Load a keyfile from disk and return the derived SigningKey.
    ///
    /// Validates format marker and confirms the stored public key matches
    /// what the seed derives to (catches file corruption cleanly).
    pub fn load(path: &Path) -> anyhow::Result<SigningKey> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read keyfile {}", path.display()))?;
        let kf: Keyfile = serde_json::from_str(&raw)
            .with_context(|| format!("parse keyfile {} as JSON", path.display()))?;

        if kf.format != Self::FORMAT {
            anyhow::bail!(
                "keyfile format mismatch: expected {}, got {}",
                Self::FORMAT,
                kf.format
            );
        }

        let seed_bytes = hex::decode(&kf.private_seed)
            .context("keyfile private_seed: invalid hex")?;
        if seed_bytes.len() != 32 {
            anyhow::bail!(
                "keyfile private_seed: expected 32 bytes, got {}",
                seed_bytes.len()
            );
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let signing_key = SigningKey::from_bytes(&seed);

        // Sanity: confirm the stored public key derives from this seed.
        let derived_pk_hex = hex::encode(signing_key.verifying_key().as_bytes());
        if derived_pk_hex != kf.public_key.to_lowercase() {
            anyhow::bail!(
                "keyfile corruption: stored public_key does not derive from stored private_seed"
            );
        }

        Ok(signing_key)
    }

    /// Save a fresh keypair to disk with 0600 permissions (unix).
    ///
    /// Refuses to overwrite an existing path unless `--force` is passed by
    /// the caller (caller responsible for enforcing that policy; this function
    /// simply errors if the path exists).
    pub fn save(path: &Path, signing_key: &SigningKey) -> anyhow::Result<()> {
        if path.exists() {
            anyhow::bail!(
                "refusing to overwrite existing keyfile at {}",
                path.display()
            );
        }

        let vk: VerifyingKey = signing_key.verifying_key();
        let kf = Keyfile {
            format: Self::FORMAT.to_string(),
            private_seed: hex::encode(signing_key.to_bytes()),
            public_key: hex::encode(vk.as_bytes()),
        };

        // Pretty-print for legibility; the file is small.
        let out = serde_json::to_string_pretty(&kf)?;
        fs::write(path, out.as_bytes())
            .with_context(|| format!("write keyfile {}", path.display()))?;

        // Best-effort unix permissions. On non-unix this is a no-op.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms)?;
        }

        Ok(())
    }
}
