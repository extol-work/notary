//! notary: reference CLI for the Attestation Notary Specification.
//!
//! Layer 1+2 commands (this build): keygen, sign, verify.
//! Layer 4/5 commands (upcoming): anchor, check, reanchor, disclose.
//! Conformance harness: vectors.
//!
//! Spec: https://github.com/extol-work/sworn/blob/main/SPEC.md
//! SAS binding: https://github.com/extol-work/sworn/blob/main/bindings/sas.md

mod attestation;
mod canonical;
mod keyfile;
mod vectors;

use anyhow::Context;
use attestation::{hex32, hex64, Attestation};
use canonical::{data_hash, sha256, CanonicalFields, SPEC_VERSION_V02};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use keyfile::Keyfile;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "attest",
    version,
    about = "Attest and notarize. Reference CLI for the Attestation Notary Specification.",
    long_about = "notary is the reference implementation of the Attestation Notary \
                  Specification. It signs factual claims as canonical byte sequences, \
                  verifies them off-chain, and notarizes their hashes to Solana \
                  Attestation Service. This build targets devnet only; a mainnet \
                  signing surface will be provisioned when the implementation stabilizes."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an Ed25519 keypair.
    Keygen(KeygenArgs),

    /// Sign a factual claim as a conforming attestation.
    Sign(SignArgs),

    /// Verify a signed attestation off-chain.
    Verify(VerifyArgs),

    /// Anchor an attestation to Solana Attestation Service. (Not yet implemented.)
    Anchor,
    /// Confirm an anchor is present on the substrate. (Not yet implemented.)
    Check,
    /// Re-anchor an attestation to a different cluster without re-signing. (Not yet implemented.)
    Reanchor,
    /// Issue or redeem a Layer 5 disclosure token. (Not yet implemented.)
    Disclose,
    /// Emit or verify golden vectors against the specification.
    Vectors(VectorsArgs),
}

#[derive(clap::Args)]
struct VectorsArgs {
    #[command(subcommand)]
    action: VectorsAction,
}

#[derive(Subcommand)]
enum VectorsAction {
    /// Regenerate the deterministic v0.2 vector file from baked test cases.
    ///
    /// Use when the spec byte layout changes (e.g., a spec_version bump).
    /// The output is the source of truth for cross-implementation conformance.
    Emit {
        /// Path to write the vectors.json file. Overwrites if exists.
        #[arg(long, short = 'o')]
        out: PathBuf,
    },
    /// Verify a vectors.json file byte-for-byte.
    ///
    /// Each vector is checked for three properties:
    ///   1. Reconstructed canonical bytes == expected_canonical_bytes_hex
    ///   2. Ed25519 signature over reconstructed bytes == expected_signature_hex
    ///   3. Signature verifies against reconstructed bytes (sanity)
    ///
    /// Exits 0 if all vectors pass all three checks. Exits 1 with per-vector
    /// diagnostics otherwise.
    Verify {
        /// Path to a vectors.json file (see fixtures/v0.2/vectors.json).
        path: PathBuf,
    },
}

#[derive(clap::Args)]
struct KeygenArgs {
    /// Path to write the new keyfile. Refuses to overwrite an existing file.
    #[arg(long, short = 'o')]
    out: PathBuf,
}

#[derive(clap::Args)]
#[command(group(clap::ArgGroup::new("subject_form").required(true).args(["subject", "subject_base58"])))]
struct SignArgs {
    /// Path to the signing keyfile.
    #[arg(long, short = 'k')]
    key: PathBuf,

    /// Subject identifier as lowercase hex (32 bytes / 64 hex chars).
    ///
    /// Interpretation is defined by the activity type's schema (§2.6):
    /// another signer's pubkey, a content hash, or an equivalent 32-byte
    /// identifier. Sign the signer's own pubkey when signer == subject.
    ///
    /// Mutually exclusive with --subject-base58. Exactly one is required.
    #[arg(long)]
    subject: Option<String>,

    /// Subject identifier as a Solana-style base58 pubkey (typically 43-44 chars,
    /// decoding to exactly 32 bytes). Convenience for pasting validator IDs and
    /// other Solana keys without hex-decoding first.
    ///
    /// Mutually exclusive with --subject. Exactly one is required.
    #[arg(long = "subject-base58")]
    subject_base58: Option<String>,

    /// Activity type as an absolute URI (SPEC §2.2).
    #[arg(long = "activity-type")]
    activity_type: String,

    /// Path to a JSON file containing the payload (RFC 8785 canonicalized on hash).
    #[arg(long, short = 'p')]
    payload: PathBuf,

    /// source_type per SPEC §9.2. Default 1 (self_reported).
    #[arg(long, default_value_t = 1)]
    source_type: u16,

    /// confidence in basis points 0..=10000. Default 10000.
    #[arg(long, default_value_t = 10000)]
    confidence: u16,

    /// witnessing_depth per SPEC §9.3. Default 0 (unspecified).
    #[arg(long, default_value_t = 0)]
    witnessing_depth: u8,

    /// attestor_relationship per SPEC §9.4. Default 0 (unknown).
    #[arg(long, default_value_t = 0)]
    attestor_relationship: u8,

    /// witness_for as lowercase hex (32 bytes). Default all zeros (no witness).
    #[arg(long, default_value = "0000000000000000000000000000000000000000000000000000000000000000")]
    witness_for: String,

    /// source_hash as lowercase hex (32 bytes). MUST be all zeros for
    /// source_type 0 or 1. Required for other source_types per SPEC §9.2.
    #[arg(long, default_value = "0000000000000000000000000000000000000000000000000000000000000000")]
    source_hash: String,

    /// retention_hint. 0 = default, -1 = indefinite, positive = expiry Unix seconds.
    #[arg(long, default_value_t = 0)]
    retention_hint: i64,

    /// Path to write the signed attestation JSON.
    #[arg(long, short = 'o')]
    out: PathBuf,
}

#[derive(clap::Args)]
struct VerifyArgs {
    /// Path to an attestation JSON file.
    attestation: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen(args) => cmd_keygen(args),
        Command::Sign(args) => cmd_sign(args),
        Command::Verify(args) => cmd_verify(args),
        Command::Vectors(args) => cmd_vectors(args),
        Command::Anchor
        | Command::Check
        | Command::Reanchor
        | Command::Disclose => {
            anyhow::bail!(
                "not yet implemented in this build. See README.md for the ship sequence."
            );
        }
    }
}

// ─── keygen ─────────────────────────────────────────────────────────

fn cmd_keygen(args: KeygenArgs) -> anyhow::Result<()> {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let public_hex = hex::encode(signing_key.verifying_key().as_bytes());

    Keyfile::save(&args.out, &signing_key)?;

    println!("wrote keyfile: {}", args.out.display());
    println!("public key:    {}", public_hex);
    println!();
    println!("⚠ devnet beta — this key is for engineering-readiness use only.");
    println!("  See https://github.com/extol-work/notary#status");
    Ok(())
}

// ─── sign ───────────────────────────────────────────────────────────

/// Decode the subject from whichever form the caller supplied. The clap
/// ArgGroup on SignArgs guarantees exactly one is Some; this function is
/// defensive against future refactors and returns a clear error if that
/// invariant were ever violated.
fn decode_subject(
    subject_hex: &Option<String>,
    subject_base58: &Option<String>,
) -> anyhow::Result<[u8; 32]> {
    match (subject_hex, subject_base58) {
        (Some(h), None) => hex32(h, "subject"),
        (None, Some(b)) => {
            let bytes = bs58::decode(b)
                .into_vec()
                .with_context(|| format!("subject-base58 is not valid base58: {}", b))?;
            let len = bytes.len();
            let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                anyhow::anyhow!(
                    "subject-base58 decoded to {} bytes, expected 32 (Solana pubkeys are 32 bytes)",
                    len
                )
            })?;
            Ok(arr)
        }
        _ => anyhow::bail!(
            "internal error: exactly one of --subject or --subject-base58 must be set (clap ArgGroup should enforce this)"
        ),
    }
}

fn cmd_sign(args: SignArgs) -> anyhow::Result<()> {
    // Load key first — cheap and fails fast on bad keyfile.
    let signing_key = Keyfile::load(&args.key)?;
    let signer_pubkey: [u8; 32] = *signing_key.verifying_key().as_bytes();

    // Load and canonicalize payload; produce data_hash.
    let payload_bytes = fs::read(&args.payload)
        .with_context(|| format!("read payload {}", args.payload.display()))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .with_context(|| format!("parse payload {} as JSON", args.payload.display()))?;
    let data_hash_bytes = data_hash(&payload)?;

    let subject_bytes = decode_subject(&args.subject, &args.subject_base58)?;
    let witness_for_bytes = hex32(&args.witness_for, "witness_for")?;
    let source_hash_bytes = hex32(&args.source_hash, "source_hash")?;

    // SPEC §2.4 sourceless-attestations rule: verifiers reject nonzero
    // source_hash when source_type is 0 or 1. Enforce at sign time.
    if (args.source_type == 0 || args.source_type == 1)
        && source_hash_bytes != canonical::ZERO_HASH
    {
        anyhow::bail!(
            "SPEC §2.4: source_type {} is sourceless; source_hash MUST be 32 zero bytes",
            args.source_type
        );
    }
    if args.confidence > 10000 {
        anyhow::bail!("confidence {} exceeds max 10000 basis points", args.confidence);
    }

    // signer_asserted_at = now.
    let signer_asserted_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64;

    // Nonce derivation per SPEC §3.4 reference form:
    // nonce = SHA-256(signer || subject || activity_hash || data_hash || salt_32)
    // salt_32 is a 32-byte OsRng draw so the nonce is unpredictable to
    // observers of the signer's earlier attestations.
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    let activity_hash_bytes = canonical::activity_hash(&args.activity_type);
    let mut nonce_input = Vec::with_capacity(32 + 32 + 32 + 32 + 32);
    nonce_input.extend_from_slice(&signer_pubkey);
    nonce_input.extend_from_slice(&subject_bytes);
    nonce_input.extend_from_slice(&activity_hash_bytes);
    nonce_input.extend_from_slice(&data_hash_bytes);
    nonce_input.extend_from_slice(&salt);
    let nonce_bytes = sha256(&nonce_input);

    let fields = CanonicalFields {
        spec_version: SPEC_VERSION_V02,
        signer: signer_pubkey,
        subject: subject_bytes,
        activity_hash: activity_hash_bytes,
        data_hash: data_hash_bytes,
        witness_for: witness_for_bytes,
        source_hash: source_hash_bytes,
        source_type: args.source_type,
        confidence: args.confidence,
        witnessing_depth: args.witnessing_depth,
        attestor_relationship: args.attestor_relationship,
        signer_asserted_at,
        retention_hint: args.retention_hint,
        nonce: nonce_bytes,
    };

    let canonical_bytes = fields.to_bytes();

    // SPEC §3.2: PureEdDSA, no pre-hashing.
    let signature: Signature = signing_key.sign(&canonical_bytes);

    // SPEC §3.2 self-check: verify our own signature before writing. Catches
    // any client-side signing bug that would produce a non-verifying output.
    signing_key
        .verifying_key()
        .verify(&canonical_bytes, &signature)
        .context("SPEC §3.2 self-check: freshly signed attestation failed local verification")?;

    let attestation = Attestation {
        spec_version: fields.spec_version,
        signer: hex::encode(fields.signer),
        subject: hex::encode(fields.subject),
        activity_type: args.activity_type.clone(),
        data_hash: hex::encode(fields.data_hash),
        witness_for: hex::encode(fields.witness_for),
        source_hash: hex::encode(fields.source_hash),
        source_type: fields.source_type,
        confidence: fields.confidence,
        witnessing_depth: fields.witnessing_depth,
        attestor_relationship: fields.attestor_relationship,
        signer_asserted_at: fields.signer_asserted_at,
        retention_hint: fields.retention_hint,
        nonce: hex::encode(fields.nonce),
        signature: hex::encode(signature.to_bytes()),
        payload: Some(payload),
    };

    attestation.validate_shape()?; // Belt-and-suspenders self-check.

    let json = serde_json::to_string_pretty(&attestation)?;
    fs::write(&args.out, json.as_bytes())
        .with_context(|| format!("write attestation {}", args.out.display()))?;

    let attestation_hash_hex = hex::encode(fields.attestation_hash());
    println!("wrote attestation: {}", args.out.display());
    println!("spec_version:      {}", fields.spec_version);
    println!("signer:            {}", hex::encode(fields.signer));
    println!("subject:           {}", hex::encode(fields.subject));
    println!("attestation_hash:  {}", attestation_hash_hex);
    println!();
    println!("⚠ devnet beta — this attestation is not yet notarized.");
    println!("  Sign is Layer 1+2 only. Layer 4 (`attest anchor`) is upcoming.");
    Ok(())
}

// ─── verify ─────────────────────────────────────────────────────────

fn cmd_verify(args: VerifyArgs) -> anyhow::Result<()> {
    let raw = fs::read_to_string(&args.attestation)
        .with_context(|| format!("read attestation {}", args.attestation.display()))?;
    let attestation: Attestation = serde_json::from_str(&raw)
        .with_context(|| format!("parse attestation {} as JSON", args.attestation.display()))?;

    // SPEC §3.1.2 step 1: reject unknown spec_version. §2.4 sourceless-rule.
    attestation.validate_shape()?;

    // SPEC §3.1.2 step 2: reconstruct canonical bytes from stored fields.
    let fields = attestation.to_canonical_fields()?;
    let canonical_bytes = fields.to_bytes();

    // SPEC §3.1.2 step 3: verify Ed25519 signature per RFC 8032 §5.1.7.
    let vk = VerifyingKey::from_bytes(&fields.signer)
        .context("signer is not a valid Ed25519 public key")?;
    let sig_bytes = hex64(&attestation.signature, "signature")?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(&canonical_bytes, &sig)
        .context("SPEC §3.1.2: signature did not verify against reconstructed canonical bytes")?;

    println!("signature:       VALID");
    println!("spec_version:    {}", fields.spec_version);
    println!("signer:          {}", attestation.signer);
    println!("subject:         {}", attestation.subject);
    println!("activity_type:   {}", attestation.activity_type);
    println!(
        "attestation_hash: {}",
        hex::encode(fields.attestation_hash())
    );

    // If the payload is present, verify SPEC §3.1.2 payload check independently.
    if let Some(payload) = &attestation.payload {
        let recomputed = data_hash(payload)?;
        if recomputed == fields.data_hash {
            println!("payload_hash:    MATCHES data_hash");
        } else {
            println!("payload_hash:    MISMATCH");
            anyhow::bail!(
                "payload hash mismatch: SPEC §3.1.2 requires SHA-256(canonicalize(payload)) == data_hash. \
                 The signature covers data_hash, so a mismatch means the payload was substituted after signing."
            );
        }
    } else {
        println!("payload:         (not included in file; signature validity is proven, payload check skipped)");
    }

    Ok(())
}

// ─── vectors ────────────────────────────────────────────────────────

fn cmd_vectors(args: VectorsArgs) -> anyhow::Result<()> {
    match args.action {
        VectorsAction::Emit { out } => {
            let file = vectors::emit_vectors()
                .context("emit vectors from baked test cases")?;
            vectors::write_vectors(&file, &out)?;
            println!("wrote {} vectors: {}", file.vectors.len(), out.display());
            println!("spec_version:    {} ({})", file.spec_version, file.spec_version_name);
            println!("canonical bytes: {}", file.canonical_bytes_length);
            for v in &file.vectors {
                println!("  - {} (signer {}…, sig {}…)",
                    v.name,
                    &v.input_fields.signer_hex[..8],
                    &v.expected_signature_hex[..8]);
            }
            Ok(())
        }
        VectorsAction::Verify { path } => {
            let (file, reports) = vectors::verify_vectors(&path)?;
            println!("vector file:     {}", path.display());
            println!("spec_version:    {} ({})", file.spec_version, file.spec_version_name);
            println!("vectors:         {}", reports.len());
            println!();

            let mut failed = 0u32;
            for r in &reports {
                if r.passed() {
                    println!("  ✓ {}", r.name);
                } else {
                    failed += 1;
                    println!("  ✗ {}", r.name);
                    println!("      canonical_bytes: {}", if r.canonical_bytes_ok { "OK" } else { "FAIL" });
                    println!("      signature:       {}", if r.signature_ok { "OK" } else { "FAIL" });
                    println!("      verify:          {}", if r.verify_ok { "OK" } else { "FAIL" });
                    for e in &r.errors {
                        println!("      • {}", e);
                    }
                }
            }
            println!();
            if failed == 0 {
                println!("PASS: {} / {} vectors conform to SPEC §3.1 and §3.2", reports.len(), reports.len());
                Ok(())
            } else {
                anyhow::bail!(
                    "FAIL: {} / {} vectors did not conform. See per-vector diagnostics above.",
                    failed, reports.len()
                );
            }
        }
    }
}
