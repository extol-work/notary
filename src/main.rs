//! notary: reference CLI for the Attestation Notary Specification.
//!
//! Layer 1+2 commands (this build): keygen, sign, verify.
//! Layer 4/5 commands (upcoming): anchor, check, reanchor, disclose.
//! Conformance harness: vectors.
//!
//! Spec: https://github.com/extol-work/sworn/blob/main/SPEC.md
//! SAS binding: https://github.com/extol-work/sworn/blob/main/bindings/sas.md

mod anchor;
mod attestation;
mod canonical;
mod devnet;
mod disclose;
mod keyfile;
mod provision;
mod sas;
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

    /// Anchor an attestation to Solana Attestation Service (Layer 4).
    Anchor(AnchorArgs),
    /// Confirm the on-chain anchor(s) match the local attestation record.
    Check(CheckArgs),
    /// Re-anchor an attestation to an additional cluster without re-signing.
    Reanchor(ReanchorArgs),
    /// Issue or redeem a Layer 5 disclosure token per SPEC §6.3.
    Disclose(DiscloseArgs),
    /// Emit or verify golden vectors against the specification.
    Vectors(VectorsArgs),

    /// Devnet provisioning: fee-payer keygen, credential + schema setup.
    Admin(AdminArgs),
}

#[derive(clap::Args)]
struct AnchorArgs {
    /// Path to the attestation JSON file (as produced by `attest sign`).
    attestation: PathBuf,

    /// Cluster to anchor to. Default: `devnet`.
    #[arg(long, default_value = "devnet")]
    cluster: String,

    /// Fee-payer keypair (also the credential authority for the reference
    /// deployment). Default: `keys/devnet-fee-payer.json`.
    #[arg(long, default_value = "keys/devnet-fee-payer.json")]
    fee_payer: PathBuf,

    /// Override the credential PDA for this cluster (base58). Optional; the
    /// notary CLI ships baked defaults for devnet.
    #[arg(long)]
    credential: Option<String>,

    /// Override the schema PDA for this cluster (base58). Optional; the notary
    /// CLI ships baked defaults for devnet.
    #[arg(long)]
    schema: Option<String>,
}

#[derive(clap::Args)]
struct CheckArgs {
    /// Path to the attestation JSON file (with one or more `anchors` entries).
    attestation: PathBuf,

    /// Only check the anchor for this cluster. Default: check every recorded
    /// anchor.
    #[arg(long)]
    cluster: Option<String>,
}

#[derive(clap::Args)]
struct ReanchorArgs {
    /// Path to the attestation JSON file.
    attestation: PathBuf,

    /// New cluster to anchor to. Required: reanchoring to the same cluster
    /// as an existing entry is a no-op and should use `anchor` instead.
    #[arg(long)]
    to: String,

    /// Fee-payer keypair. Default: `keys/devnet-fee-payer.json`.
    #[arg(long, default_value = "keys/devnet-fee-payer.json")]
    fee_payer: PathBuf,

    /// Override the credential PDA for the new cluster.
    #[arg(long)]
    credential: Option<String>,

    /// Override the schema PDA for the new cluster.
    #[arg(long)]
    schema: Option<String>,
}

#[derive(clap::Args)]
struct DiscloseArgs {
    #[command(subcommand)]
    action: DiscloseAction,
}

#[derive(Subcommand)]
enum DiscloseAction {
    /// Mint a single-use disclosure token authorizing payload retrieval.
    ///
    /// The token is signed by the attestation's signing key (SPEC §6.3
    /// signer-authorized). The keyfile you pass MUST match the attestation's
    /// signer field; a mismatch is caught before any file is written.
    Issue {
        /// Path to the attestation JSON to authorize.
        #[arg(long, short = 'a')]
        attestation: PathBuf,

        /// Signing key that produced the attestation.
        #[arg(long, short = 'k')]
        key: PathBuf,

        /// Token lifetime in seconds. SPEC §6.3 recommends 60..=604800 for
        /// single-use tokens. Default: 3600 (one hour).
        #[arg(long, default_value_t = 3600)]
        lifetime_secs: i64,

        /// Explicitly designate this token as multi-use per SPEC §6.3. If
        /// unset, the token is single-use.
        #[arg(long)]
        multi_use: bool,

        /// Bypass the 7-day ceiling for single-use tokens. Refused unless
        /// the caller passes this flag with intent.
        #[arg(long)]
        allow_long_lifetime: bool,

        /// Path to write the disclosure token JSON.
        #[arg(long, short = 'o')]
        out: PathBuf,
    },

    /// Verify a disclosure token and (if all checks pass) print the payload.
    ///
    /// Consumes the token via the single-use ledger for single-use tokens.
    /// Multi-use tokens are not tracked.
    Redeem {
        /// Path to the attestation JSON that contains the payload.
        #[arg(long, short = 'a')]
        attestation: PathBuf,

        /// Path to the disclosure token JSON.
        #[arg(long, short = 't')]
        token: PathBuf,

        /// Ledger path for single-use enforcement. Default:
        /// `~/.notary/consumed-tokens.json`.
        #[arg(long)]
        ledger: Option<PathBuf>,

        /// Write the payload here rather than stdout.
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,
    },
}

#[derive(clap::Args)]
struct AdminArgs {
    #[command(subcommand)]
    action: AdminAction,
}

#[derive(Subcommand)]
enum AdminAction {
    /// Generate a Solana devnet keypair for paying fees and rent.
    ///
    /// Writes a standard Solana JSON-array keypair file (compatible with
    /// solana-keygen and the solana CLI). Prints the base58 pubkey so the
    /// operator can fund it via the devnet faucet.
    ///
    /// Refuses to overwrite an existing keypair. Delete or move it
    /// explicitly if you intend to replace it.
    KeygenFeePayer {
        /// Path to write the keypair file. Default: `keys/devnet-fee-payer.json`.
        #[arg(long, short = 'o', default_value = "keys/devnet-fee-payer.json")]
        out: PathBuf,
    },
    /// Query the devnet balance of a base58 pubkey.
    ///
    /// Convenience so the operator does not need the solana CLI installed
    /// to confirm the fee-payer was funded before provisioning.
    Balance {
        /// Base58 pubkey to query. Defaults to reading the pubkey from the
        /// keypair at `keys/devnet-fee-payer.json`.
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// Create the SAS credential PDA on devnet (SAS instruction 0).
    ///
    /// One-time per environment. Idempotent: if the PDA already exists,
    /// prints the address and exits success. The credential authority is
    /// the fee-payer keypair.
    ProvisionCredential {
        /// Path to the fee-payer keypair (also the credential authority).
        #[arg(long, default_value = "keys/devnet-fee-payer.json")]
        fee_payer: PathBuf,
    },
    /// Create the SAS schema PDA under the notary CLI credential (SAS instruction 1).
    ///
    /// One-time per environment. Idempotent: if the PDA already exists,
    /// prints the address and exits success. Schema layout is fixed per
    /// bindings/sas.md §5 (v0.2 receipt: spec_version + attestation_hash +
    /// signer_asserted_at).
    ProvisionSchema {
        /// Path to the fee-payer keypair (also the credential authority).
        #[arg(long, default_value = "keys/devnet-fee-payer.json")]
        fee_payer: PathBuf,
    },
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
        Command::Admin(args) => cmd_admin(args),
        Command::Anchor(args) => cmd_anchor(args),
        Command::Check(args) => cmd_check(args),
        Command::Reanchor(args) => cmd_reanchor(args),
        Command::Disclose(args) => cmd_disclose(args),
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
        anchors: Vec::new(),
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

// ─── admin ─────────────────────────────────────────────────────────

fn cmd_admin(args: AdminArgs) -> anyhow::Result<()> {
    match args.action {
        AdminAction::KeygenFeePayer { out } => cmd_admin_keygen_fee_payer(out),
        AdminAction::Balance { pubkey } => cmd_admin_balance(pubkey),
        AdminAction::ProvisionCredential { fee_payer } => {
            cmd_admin_provision_credential(fee_payer)
        }
        AdminAction::ProvisionSchema { fee_payer } => cmd_admin_provision_schema(fee_payer),
    }
}

fn cmd_admin_keygen_fee_payer(out: PathBuf) -> anyhow::Result<()> {
    let pubkey_base58 = devnet::keygen_fee_payer(&out)?;

    println!("wrote devnet fee-payer keypair: {}", out.display());
    println!("pubkey (base58):                {}", pubkey_base58);
    println!();
    println!("Next: fund this pubkey on devnet before running provisioning.");
    println!("  solana airdrop 1 {} --url devnet", pubkey_base58);
    println!("  or use https://faucet.solana.com (pick devnet)");
    println!();
    println!("⚠ devnet only. Do not fund this pubkey with mainnet SOL.");
    println!("  See docs/devnet-setup.md for the full provisioning handshake.");
    Ok(())
}

fn cmd_admin_balance(pubkey_arg: Option<String>) -> anyhow::Result<()> {
    use solana_client::rpc_client::RpcClient;
    use solana_sdk::commitment_config::CommitmentConfig;
    use solana_sdk::pubkey::Pubkey;
    use std::str::FromStr;

    let pubkey = match pubkey_arg {
        Some(s) => Pubkey::from_str(&s).context("parse --pubkey as base58")?,
        None => {
            let default_path = PathBuf::from("keys/devnet-fee-payer.json");
            devnet::load_keypair(&default_path)
                .context("no --pubkey given and default keypair not readable at keys/devnet-fee-payer.json")?
                .pubkey_base58()
                .parse()
                .expect("stored pubkey parses as base58 pubkey")
        }
    };

    let client = RpcClient::new_with_commitment(
        devnet::DEVNET_RPC.to_string(),
        CommitmentConfig::confirmed(),
    );
    let lamports = client
        .get_balance(&pubkey)
        .with_context(|| format!("query balance for {pubkey}"))?;

    println!("pubkey:   {}", pubkey);
    println!("cluster:  devnet ({})", devnet::DEVNET_RPC);
    println!(
        "balance:  {} lamports = {} SOL",
        lamports,
        lamports as f64 / 1_000_000_000.0
    );
    if lamports == 0 {
        println!();
        println!("⚠ zero balance. Fund via https://faucet.solana.com or:");
        println!("  solana airdrop 1 {} --url devnet", pubkey);
    }
    Ok(())
}

fn cmd_admin_provision_credential(fee_payer_path: PathBuf) -> anyhow::Result<()> {
    use solana_client::rpc_client::RpcClient;
    use solana_sdk::commitment_config::CommitmentConfig;
    use solana_sdk::signature::Signer as SolanaSigner;
    use solana_sdk::transaction::Transaction;

    let fp = devnet::load_keypair(&fee_payer_path)?;
    let authority = fp.sdk_keypair.pubkey();
    let (credential_pda, _bump) =
        sas::find_credential_pda(&authority, provision::CREDENTIAL_NAME_DEVNET.as_bytes());

    println!("fee-payer / authority: {}", authority);
    println!("credential name:       {}", provision::CREDENTIAL_NAME_DEVNET);
    println!("credential PDA:        {}", credential_pda);
    println!();

    let client = RpcClient::new_with_commitment(
        devnet::DEVNET_RPC.to_string(),
        CommitmentConfig::confirmed(),
    );

    // Idempotency check: SAS returns an account for an existing PDA.
    if client.get_account(&credential_pda).is_ok() {
        println!("credential already exists on devnet. Nothing to do.");
        println!("(SAS_CREDENTIAL for env: {})", credential_pda);
        return Ok(());
    }

    let ix = provision::create_credential_ix(
        &authority,
        &authority,
        &credential_pda,
        provision::CREDENTIAL_NAME_DEVNET,
        &[authority],
    );
    let recent_blockhash = client
        .get_latest_blockhash()
        .context("get_latest_blockhash")?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority),
        &[&fp.sdk_keypair],
        recent_blockhash,
    );
    let sig = client
        .send_and_confirm_transaction_with_spinner(&tx)
        .context("send create_credential tx")?;

    println!("credential created.");
    println!("tx:                    {}", sig);
    println!("SAS_CREDENTIAL:        {}", credential_pda);
    Ok(())
}

fn cmd_admin_provision_schema(fee_payer_path: PathBuf) -> anyhow::Result<()> {
    use solana_client::rpc_client::RpcClient;
    use solana_sdk::commitment_config::CommitmentConfig;
    use solana_sdk::signature::Signer as SolanaSigner;
    use solana_sdk::transaction::Transaction;

    let fp = devnet::load_keypair(&fee_payer_path)?;
    let authority = fp.sdk_keypair.pubkey();
    let (credential_pda, _) =
        sas::find_credential_pda(&authority, provision::CREDENTIAL_NAME_DEVNET.as_bytes());
    let (schema_pda, _) = sas::find_schema_pda(
        &credential_pda,
        provision::SCHEMA_NAME.as_bytes(),
        provision::SCHEMA_VERSION,
    );

    println!("fee-payer / authority: {}", authority);
    println!("credential PDA:        {}", credential_pda);
    println!("schema name:           {} (v{})", provision::SCHEMA_NAME, provision::SCHEMA_VERSION);
    println!("schema PDA:            {}", schema_pda);
    println!();

    let client = RpcClient::new_with_commitment(
        devnet::DEVNET_RPC.to_string(),
        CommitmentConfig::confirmed(),
    );

    // Credential must exist first.
    if client.get_account(&credential_pda).is_err() {
        anyhow::bail!(
            "credential PDA {} does not exist. Run `attest admin provision-credential` first.",
            credential_pda
        );
    }

    // Idempotency check.
    if client.get_account(&schema_pda).is_ok() {
        println!("schema already exists on devnet. Nothing to do.");
        println!("(SAS_SCHEMA for env: {})", schema_pda);
        return Ok(());
    }

    let ix = provision::create_schema_ix(
        &authority,
        &authority,
        &credential_pda,
        &schema_pda,
        provision::SCHEMA_NAME,
        provision::SCHEMA_DESCRIPTION,
        provision::NOTARY_V2_SCHEMA_LAYOUT,
        provision::NOTARY_V2_FIELD_NAMES,
    );
    let recent_blockhash = client
        .get_latest_blockhash()
        .context("get_latest_blockhash")?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority),
        &[&fp.sdk_keypair],
        recent_blockhash,
    );
    let sig = client
        .send_and_confirm_transaction_with_spinner(&tx)
        .context("send create_schema tx")?;

    println!("schema created.");
    println!("tx:                    {}", sig);
    println!("SAS_SCHEMA:            {}", schema_pda);
    Ok(())
}

// ─── anchor (Layer 4) ────────────────────────────────────────────────

fn cmd_anchor(args: AnchorArgs) -> anyhow::Result<()> {
    let cluster = anchor::Cluster::parse(&args.cluster)?;
    let credential = parse_optional_pubkey(&args.credential, "--credential")?;
    let schema = parse_optional_pubkey(&args.schema, "--schema")?;

    let att_json = fs::read_to_string(&args.attestation)
        .with_context(|| format!("read {}", args.attestation.display()))?;
    let mut att: Attestation = serde_json::from_str(&att_json)
        .with_context(|| format!("parse {} as attestation JSON", args.attestation.display()))?;
    att.validate_shape()?;

    let fee_payer = devnet::load_keypair(&args.fee_payer)?;

    println!("attestation:           {}", args.attestation.display());
    println!("cluster:               {}", cluster.as_str());
    println!("fee-payer:             {}", fee_payer.pubkey_base58());
    println!();

    let opts = anchor::AnchorOpts {
        cluster,
        credential,
        schema,
    };
    let outcome = anchor::anchor(&att, &fee_payer, opts)?;

    let record = match outcome {
        anchor::AnchorOutcome::Anchored(r) => {
            println!("anchored.");
            r
        }
        anchor::AnchorOutcome::AlreadyAnchored(r) => {
            println!("already anchored on this cluster. Nothing to do.");
            r
        }
    };
    println!("credential:            {}", record.credential);
    println!("schema:                {}", record.schema);
    println!("attestation PDA:       {}", record.attestation_pda);
    if !record.tx_signature.is_empty() {
        println!("tx:                    {}", record.tx_signature);
    }
    if record.anchored_at_block_time != 0 {
        println!(
            "anchored at:           slot {}, block time {}",
            record.anchored_at_slot, record.anchored_at_block_time
        );
    }
    if record.beta {
        println!();
        println!("(devnet beta anchor: this is not a mainnet notarization.)");
    }

    // Append to attestation.anchors if not already present. Write back.
    let already_recorded = att
        .anchors
        .iter()
        .any(|r| r.attestation_pda == record.attestation_pda && r.cluster == record.cluster);
    if !already_recorded {
        att.anchors.push(record);
        let json = serde_json::to_string_pretty(&att)?;
        fs::write(&args.attestation, json.as_bytes())
            .with_context(|| format!("write {}", args.attestation.display()))?;
        println!();
        println!("attestation.json updated with new anchor record.");
    }

    Ok(())
}

// ─── check (Layer 4 verification) ────────────────────────────────────

fn cmd_check(args: CheckArgs) -> anyhow::Result<()> {
    let att_json = fs::read_to_string(&args.attestation)
        .with_context(|| format!("read {}", args.attestation.display()))?;
    let att: Attestation = serde_json::from_str(&att_json)
        .with_context(|| format!("parse {} as attestation JSON", args.attestation.display()))?;
    att.validate_shape()?;

    if att.anchors.is_empty() {
        anyhow::bail!(
            "attestation {} has no anchors. Run `attest anchor` first.",
            args.attestation.display()
        );
    }

    let cluster_filter = args.cluster;
    let mut checked = 0usize;
    let mut passing = 0usize;

    for record in &att.anchors {
        if let Some(ref want) = cluster_filter {
            if &record.cluster != want {
                continue;
            }
        }

        println!("cluster:               {}", record.cluster);
        println!("attestation PDA:       {}", record.attestation_pda);

        let result = anchor::check(record, &att)?;
        checked += 1;

        if result.matches_local {
            passing += 1;
            println!("status:                MATCHES local record");
        } else {
            println!("status:                MISMATCH");
            for d in &result.diagnostics {
                println!("  · {}", d);
            }
        }
        println!(
            "on-chain spec_version: {}",
            result.on_chain_spec_version
        );
        println!(
            "on-chain hash:         {}",
            hex::encode(result.on_chain_attestation_hash)
        );
        println!(
            "on-chain signer time:  {}",
            result.on_chain_signer_asserted_at
        );
        println!();
    }

    if checked == 0 {
        anyhow::bail!(
            "no anchors matched the filter (--cluster {:?}). Available: {:?}",
            cluster_filter,
            att.anchors.iter().map(|r| &r.cluster).collect::<Vec<_>>()
        );
    }

    if passing == checked {
        println!("PASS: {passing}/{checked} anchor(s) match the local record");
        Ok(())
    } else {
        anyhow::bail!("FAIL: {}/{} anchor(s) matched", passing, checked);
    }
}

// ─── reanchor (Layer 4 additional-cluster commitment) ────────────────

fn cmd_reanchor(args: ReanchorArgs) -> anyhow::Result<()> {
    let cluster = anchor::Cluster::parse(&args.to)?;

    // Load and confirm the attestation is not already anchored to this cluster.
    let att_json = fs::read_to_string(&args.attestation)
        .with_context(|| format!("read {}", args.attestation.display()))?;
    let att: Attestation = serde_json::from_str(&att_json)
        .with_context(|| format!("parse {} as attestation JSON", args.attestation.display()))?;
    if let Some(existing) = att.anchors.iter().find(|r| r.cluster == cluster.as_str()) {
        anyhow::bail!(
            "attestation is already anchored to {}: {}. Use `attest anchor` \
             for idempotent re-checking on the same cluster; reanchor requires \
             a new cluster.",
            existing.cluster,
            existing.attestation_pda
        );
    }

    // Delegate to the normal anchor path with the new cluster. The signature
    // and canonical bytes are unchanged; only a new SAS PDA is created.
    let anchor_args = AnchorArgs {
        attestation: args.attestation,
        cluster: cluster.as_str().to_string(),
        fee_payer: args.fee_payer,
        credential: args.credential,
        schema: args.schema,
    };
    cmd_anchor(anchor_args)
}

fn parse_optional_pubkey(
    s: &Option<String>,
    label: &str,
) -> anyhow::Result<Option<solana_sdk::pubkey::Pubkey>> {
    use std::str::FromStr;
    match s {
        None => Ok(None),
        Some(s) => Ok(Some(
            solana_sdk::pubkey::Pubkey::from_str(s)
                .with_context(|| format!("parse {label} as base58 pubkey"))?,
        )),
    }
}

// ─── disclose (Layer 5) ────────────────────────────────────────────

fn cmd_disclose(args: DiscloseArgs) -> anyhow::Result<()> {
    match args.action {
        DiscloseAction::Issue {
            attestation,
            key,
            lifetime_secs,
            multi_use,
            allow_long_lifetime,
            out,
        } => cmd_disclose_issue(
            attestation,
            key,
            lifetime_secs,
            !multi_use,
            allow_long_lifetime,
            out,
        ),
        DiscloseAction::Redeem {
            attestation,
            token,
            ledger,
            out,
        } => cmd_disclose_redeem(attestation, token, ledger, out),
    }
}

fn cmd_disclose_issue(
    attestation_path: PathBuf,
    key_path: PathBuf,
    lifetime_secs: i64,
    single_use: bool,
    allow_long_lifetime: bool,
    out: PathBuf,
) -> anyhow::Result<()> {
    if out.exists() {
        anyhow::bail!(
            "refusing to overwrite existing token at {}. \
             Delete or move it explicitly if you intend to replace it.",
            out.display()
        );
    }

    let signing_key = Keyfile::load(&key_path)?;

    let att_bytes = fs::read(&attestation_path)
        .with_context(|| format!("read attestation {}", attestation_path.display()))?;
    let att: Attestation = serde_json::from_slice(&att_bytes)
        .with_context(|| format!("parse attestation {} as JSON", attestation_path.display()))?;
    att.validate_shape()?;

    let token = disclose::issue(&att, &signing_key, lifetime_secs, single_use, allow_long_lifetime)?;
    let json = serde_json::to_string_pretty(&token)?;
    fs::write(&out, json.as_bytes())
        .with_context(|| format!("write token {}", out.display()))?;

    println!("wrote disclosure token: {}", out.display());
    println!("token_id:               {}", token.token_id);
    println!("covers attestation:     {}", token.attestation_hash);
    println!("expires_at:             {} (Unix seconds)", token.expires_at);
    println!(
        "kind:                   {}",
        if token.single_use { "single-use" } else { "multi-use" }
    );
    println!();
    if token.single_use {
        println!("Single-use per SPEC §6.3: this token can be redeemed exactly once.");
        println!("Consumption is tracked in the ledger (~/.notary/consumed-tokens.json by default).");
    } else {
        println!("⚠ Multi-use token per SPEC §6.3. The single-use property is EXPLICITLY WAIVED.");
        println!("  Any holder can redeem repeatedly until expiration.");
    }
    Ok(())
}

fn cmd_disclose_redeem(
    attestation_path: PathBuf,
    token_path: PathBuf,
    ledger_path: Option<PathBuf>,
    out: Option<PathBuf>,
) -> anyhow::Result<()> {
    let att_bytes = fs::read(&attestation_path)
        .with_context(|| format!("read attestation {}", attestation_path.display()))?;
    let att: Attestation = serde_json::from_slice(&att_bytes)
        .with_context(|| format!("parse attestation {} as JSON", attestation_path.display()))?;
    att.validate_shape()?;

    let token_bytes = fs::read(&token_path)
        .with_context(|| format!("read token {}", token_path.display()))?;
    let token: disclose::DisclosureToken = serde_json::from_slice(&token_bytes)
        .with_context(|| format!("parse token {} as JSON", token_path.display()))?;

    let ledger = match ledger_path {
        Some(p) => p,
        None => disclose::default_ledger_path()?,
    };

    // Single-use gate BEFORE signature verification. This is important: a
    // second redemption of a consumed token surfaces as AlreadyConsumed rather
    // than passing signature verification and then failing at consume time.
    // The distinct error class is what SPEC §6.3 requires.
    if token.single_use && disclose::is_consumed(&ledger, &token.token_id)? {
        anyhow::bail!(
            "SPEC §6.3: single-use token {}… has already been redeemed. \
             Consumption recorded at {}. Issue a fresh token; single-use is a hard property.",
            token.token_id.chars().take(16).collect::<String>(),
            ledger.display()
        );
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs() as i64;

    let payload = match disclose::verify_token(&att, &token, now_secs) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("REDEEM FAILED ({}): {}", e.class(), e);
            anyhow::bail!("token verification failed");
        }
    };

    // Record consumption AFTER successful verification. For single-use tokens
    // this makes the redemption stick. Multi-use tokens are a no-op here.
    disclose::consume_token_in_ledger(&ledger, &token, now_secs)?;

    // Write payload to stdout or file. Serialize with the same key ordering
    // discipline as sign uses (preserve_order), so a caller comparing bytes
    // sees a stable form.
    let payload_bytes = serde_json::to_vec_pretty(&payload)
        .map_err(|e| anyhow::anyhow!("serialize payload for output: {e}"))?;
    match out {
        Some(path) => {
            fs::write(&path, &payload_bytes)
                .with_context(|| format!("write payload {}", path.display()))?;
            println!("token_id:              {}", token.token_id);
            println!("covers attestation:    {}", token.attestation_hash);
            println!("kind:                  {}", if token.single_use { "single-use (consumed)" } else { "multi-use" });
            println!("payload_hash:          MATCHES data_hash");
            println!("wrote payload:         {}", path.display());
        }
        None => {
            eprintln!("token_id:              {}", token.token_id);
            eprintln!("covers attestation:    {}", token.attestation_hash);
            eprintln!("kind:                  {}", if token.single_use { "single-use (consumed)" } else { "multi-use" });
            eprintln!("payload_hash:          MATCHES data_hash");
            eprintln!("--- payload ---");
            use std::io::Write;
            std::io::stdout()
                .write_all(&payload_bytes)
                .context("write payload to stdout")?;
            println!();
        }
    }
    Ok(())
}
