# Devnet setup

This document describes how the notary CLI's Layer 4 (SAS notarization on
Solana devnet) will be provisioned. As of this commit, only the constants
and PDA-derivation helpers are in place (see `src/sas.rs`); the actual
`attest anchor`, `attest check`, and `attest reanchor` commands land in the
next commit alongside the credential and schema provisioning code.

The scope of this document is what the next session will do and what
operator input is needed before that session starts.

---

## What the CLI needs on-chain

A conforming notary deployment requires two pieces of SAS state to exist on
devnet before any attestation can be anchored:

1. **A credential PDA** derived under a keypair we control (the "authority").
   The credential is the top-level object; it names who can add or remove
   authorized signers. For the notary CLI we use a dedicated credential
   distinct from Extol's community-attestation credential (`extol-devnet-v1`
   and similar). Proposed name: `notary-cli-devnet`.

2. **A schema PDA** under that credential, with a 42-byte data section
   layout: `spec_version (2 bytes) || attestation_hash (32 bytes) ||
   signer_asserted_at (8 bytes)`. Proposed name: `ans-v2-notary`, version 1.

Both are one-time provisioning steps per environment. Once provisioned, the
credential and schema addresses are baked into the CLI as configuration
(devnet defaults; overridable via `--credential` and `--schema` for future
environments).

## What we need before provisioning

A Solana devnet keypair with enough SOL to pay for:

- Rent for the credential PDA (approximately 0.002 SOL)
- Rent for the schema PDA (approximately 0.003 SOL)
- Ongoing transaction fees for each `attest anchor` operation (approximately
  0.000005 SOL per anchor, plus rent for the attestation account of
  approximately 0.0007 SOL)

For the initial provisioning and a comfortable devnet operating buffer, one
devnet SOL is more than sufficient (approximately 1300 anchor operations
worth of rent, or unlimited test iterations of provisioning cycles).

## Where the fee-payer keypair lives

The keypair file will be generated locally when the next session starts. It
will live at `keys/devnet-fee-payer.json` in Solana's standard JSON-array
format. That path is gitignored (see `.gitignore` `keys/` and
`/devnet-fee-payer.json` entries). The pubkey is safe to share; the private
seed inside the file must not leave the local machine.

## Handshake with the operator

1. Next session generates the keypair, prints the base58 pubkey.
2. Operator funds the pubkey via
   [faucet.solana.com](https://faucet.solana.com) or
   `solana airdrop 1 <pubkey> --url devnet` (needs 1 devnet SOL).
3. Session runs the provisioning step (`attest admin provision-credential`
   and `attest admin provision-schema` or equivalent, TBD in that commit).
4. Session bakes the resulting credential and schema addresses into the CLI
   as devnet defaults and adds them to this document.
5. Session verifies with a full round-trip:
   `attest sign` → `attest anchor` → `attest check`.

## What operators of other deployments do

The same steps apply to any operator who wants to run the notary CLI
against their own devnet or mainnet credential (rather than the reference
deployment's credential). The provisioning subcommands accept
`--authority` and `--credential-name` so different operators produce
different PDAs without collision. Once provisioned, the operator can pass
`--credential <pubkey> --schema <pubkey>` to `attest anchor` to target
their own deployment.

## Non-goals for this document

- Mainnet setup. Mainnet provisioning waits until Umbriel confirms the
  essay-endorsement surface is going live in production (per the EXT-248
  scope). Until then, mainnet is a note-only concern.
- Rotation. Key rotation for the fee-payer or credential authority is
  operator territory and not covered here.
- Multi-signer credential setups. SAS supports multiple authorized
  signers per credential (Cortex uses this pattern for KMS-backed signing).
  The notary CLI reference deployment uses a single signer; operators who
  need multi-signer can extend without spec changes.
