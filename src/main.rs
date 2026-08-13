//! notary: reference CLI for the Attestation Notary Specification.
//!
//! This scaffolding commit reserves the binary name and locks the CLI shape.
//! Command implementations land in subsequent commits following the sequence:
//!
//!   1. keygen, sign, verify  (Layer 1+2 core, no network)
//!   2. vectors emit/verify   (golden vector conformance)
//!   3. anchor, check, reanchor (Layer 4, devnet)
//!   4. disclose issue/redeem (Layer 5)
//!
//! Spec: https://github.com/extol-work/sworn/blob/main/SPEC.md
//! SAS binding: https://github.com/extol-work/sworn/blob/main/bindings/sas.md

use clap::{Parser, Subcommand};

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
    Keygen,
    /// Sign a factual claim as a conforming attestation.
    Sign,
    /// Verify a signed attestation off-chain.
    Verify,
    /// Anchor an attestation to Solana Attestation Service.
    Anchor,
    /// Confirm an anchor is present on the substrate.
    Check,
    /// Re-anchor an attestation to a different cluster without re-signing.
    Reanchor,
    /// Issue or redeem a Layer 5 disclosure token.
    Disclose,
    /// Emit or verify golden vectors against the specification.
    Vectors,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen | Command::Sign | Command::Verify | Command::Anchor
        | Command::Check | Command::Reanchor | Command::Disclose | Command::Vectors => {
            anyhow::bail!(
                "not yet implemented: this is a scaffolding commit. See README.md for the ship sequence."
            );
        }
    }
}
