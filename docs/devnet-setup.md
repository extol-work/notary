# Devnet setup

The notary CLI's Layer 4 (SAS notarization on Solana devnet) is provisioned.
The reference deployment addresses below are baked into `src/sas.rs`
(`devnet_reference` module) and are the defaults for `attest anchor`,
`attest check`, and `attest reanchor` on devnet.

## Reference deployment addresses (devnet)

| Item | Address |
|---|---|
| SAS program | `22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG` |
| Credential (`notary-cli-devnet`) | `2wp93cFgFeZANui2rbDbFFkCju1f8NaaBBa9uuXeKZQw` |
| Schema (`ans-v2-notary` v1) | `Cnu2C6jK6GpUdjWXjacJqQyzYwzr3mXpRKSj7gmrn4wW` |
| Fee-payer / credential authority | `ySRnUCkb6FFgz6NThWdJbRbQJJdwb2uo4QMvG5TbSez` |

Provisioned 2026-08-13. Schema layout `[1, 13, 8]` (U16, VecU8, I64)
corresponding to the ANS v0.2 receipt: `spec_version || attestation_hash ||
signer_asserted_at`.

## Wire format note

`bindings/sas.md §5` names the semantic payload as 42 bytes. On the actual
SAS account, the data section is 46 bytes: a `VecU8` type carries a 4-byte
little-endian length prefix, and SAS has no fixed-length byte array type
suitable for the 32-byte hash. Layout:

```
  offset  0.. 2   spec_version           (u16 LE)                = 2 bytes
  offset  2.. 6   attestation_hash len   (u32 LE, always = 32)   = 4 bytes
  offset  6..38   attestation_hash       (32 bytes)              = 32 bytes
  offset 38..46   signer_asserted_at     (i64 LE)                = 8 bytes
```

The extra 4 bytes do not weaken the non-walkability property (the PDA seed
is `SHA-256(canonical_bytes)`, opaque with respect to every field). It is a
small correction that should land as a doc fix on `extol-work/sworn/bindings/sas.md`.

## Provisioning a fresh deployment

An operator who wants their own credential (rather than using the reference
deployment) runs:

```
attest admin keygen-fee-payer               # generate keypair, print pubkey
# operator funds the pubkey with ~1 devnet SOL via
#   solana airdrop 1 <pubkey> --url devnet
#   or https://faucet.solana.com
attest admin balance                        # confirm funding landed
attest admin provision-credential           # SAS instruction 0
attest admin provision-schema               # SAS instruction 1
```

All four subcommands accept `--fee-payer <path>` if the keypair is not at
`keys/devnet-fee-payer.json`. `provision-credential` and `provision-schema`
are idempotent: re-running them prints the existing address and exits
success. Total provisioning cost is approximately 0.004 SOL.

## Overriding the reference deployment

`attest anchor`, `attest check`, and `attest reanchor` (upcoming) accept
`--credential <base58>` and `--schema <base58>` to target a non-reference
deployment. With no flags, they use the addresses above.

## Fee-payer keypair storage

The keypair lives at `keys/devnet-fee-payer.json` in Solana's standard
JSON-array format. Compatible with `solana-keygen`, `solana-cli`, and any
wallet that reads Solana keypair files.

- Path is gitignored (`.gitignore` blocks `/keys/`).
- File permissions are restricted to owner-read-only on creation.
- The pubkey is safe to share; the seed inside must not leave the local
  machine.

## Non-goals

- **Mainnet setup.** Mainnet provisioning waits until Umbriel confirms the
  essay-endorsement surface is going live in production (per the EXT-248
  scope). Until then, mainnet is a note-only concern.
- **Rotation.** Key rotation for the fee-payer or credential authority is
  operator territory and not covered here.
- **Multi-signer credential setups.** SAS supports multiple authorized
  signers per credential (Cortex uses this pattern for KMS-backed signing).
  The notary CLI reference deployment uses a single signer; operators who
  need multi-signer can extend without spec changes.
