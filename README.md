# notary

Reference command-line implementation of the [Attestation Notary Specification](https://github.com/extol-work/sworn).

**Attest and notarize.**

## Status

**Beta. Devnet only.** This is an engineering-readiness build. The CLI exercises the specification against the current devnet cluster; a mainnet signing surface will be provisioned when the reference implementation stabilizes. Attestations produced against devnet are not durable, are not endorsements of production infrastructure, and should not be used to make legal or economic claims.

Version numbering follows semver 0.x while the specification remains draft v0.2.

## What this is

A single-binary Rust CLI that lets you:

- Generate an Ed25519 keypair (`attest keygen`)
- Sign a factual claim as an Attestation Notary conforming attestation (`attest sign`)
- Verify a signed attestation off-chain (`attest verify`)
- Anchor an attestation to Solana Attestation Service on devnet (`attest anchor`)
- Confirm an anchor is present on the substrate (`attest check`)
- Re-anchor an attestation to a different cluster without re-signing (`attest reanchor`)
- Issue and redeem single-use disclosure tokens per SPEC §6.3 (`attest disclose`)
- Round-trip against the specification's golden vectors (`attest vectors`)

Each command corresponds to a concrete layer of the specification. The CLI is intentionally the smallest surface that exercises Layers 1 through 5 end-to-end.

## What this is not

Not a wallet. Not a signer service. Not a substrate. This binary reads and writes attestation files, delegates key custody to the operator (via keyfiles), and speaks to Solana over public RPC. Any deployment that needs KMS-managed keys, hardware wallets, or a signing service should treat this CLI as a reference for correctness and layer its own custody above it.

## Install

Cargo:

```
cargo install --path .
```

Prebuilt binaries and a `cargo install` shortcut against crates.io ship with the first stable release.

## Usage

Not yet available. This scaffolding commit reserves the repository and locks in the naming; the operational commands ship in the next work session.

See [SPEC.md](https://github.com/extol-work/sworn/blob/main/SPEC.md) for what the CLI is implementing against, and [bindings/sas.md](https://github.com/extol-work/sworn/blob/main/bindings/sas.md) for the Solana binding this CLI targets.

## Contributing

Not yet accepting external contributions. The reference implementation is still stabilizing against the specification. Issues welcome for anything that reads incorrectly against SPEC.md.

## License

Apache 2.0. See [LICENSE](./LICENSE).
