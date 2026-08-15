# notary

Reference command-line implementation of the [Attestation Notary Specification](https://github.com/extol-work/sworn).

**Attest and notarize.**

## Status

**Beta. Devnet only.** This is an engineering-readiness build. The CLI exercises the specification against the current devnet cluster; a mainnet signing surface will be provisioned when the reference implementation stabilizes. Attestations produced against devnet are not durable, are not endorsements of production infrastructure, and should not be used to make legal or economic claims.

Version numbering follows semver 0.x while the specification remains draft v0.2.

## Summary

A single-binary Rust CLI that lets you:

- Generate an Ed25519 keypair (`attest keygen`)
- Sign a factual claim as an Attestation Notary conforming attestation (`attest sign`)
- Verify a signed attestation off-chain: signature valid, payload matches `data_hash` (`attest verify`)
- Anchor an attestation to Solana Attestation Service on devnet (`attest anchor`). Anchoring the same attestation to a second cluster is the same command with a different `--cluster`; each anchor lives in its own sibling file so the signed attestation itself stays immutable.
- Confirm on-chain anchor(s) match the local record (`attest check`)
- Run verify + check together with a unified verdict (`attest confirm`) the "did they send me what they said and is it real?" command for a bundle from a third party
- Issue and redeem disclosure tokens per SPEC §6.3, single-use by default with `--multi-use` opt-in (`attest disclose`)
- Round-trip against the specification's golden vectors (`attest vectors`)

Each command corresponds to a concrete layer of the specification. The CLI is intentionally the smallest surface that exercises Layers 1 through 5 end-to-end.

## Install

Cargo, from a git clone:

```
git clone https://github.com/extol-work/notary && cd notary
cargo install --path . --locked
```

Or directly from GitHub:

```
cargo install --git https://github.com/extol-work/notary --locked
```

The `--locked` flag is important: it tells cargo to use the exact dependency versions in `Cargo.lock` rather than re-resolving. Without it, cargo picks the newest compatible versions each time, which occasionally lands on broken combinations in the Solana SDK dependency tree.

The repo pins its Rust toolchain to 1.88.0 via `rust-toolchain.toml`. If rustup is installed, it will transparently download that toolchain on first invocation. No global toolchain change is needed. Rust older than 1.88 will fail on transitive dependencies (`serde_with_macros`, `time`) that require modern rustc.

Prebuilt binaries and a `cargo install` shortcut against crates.io ship with the first stable release.

## Try it

The full spec is exercisable from the CLI. Layers 1, 2, and 5 run offline; Layer 4 anchoring needs a funded Solana devnet keypair. The commands below assume you have `attest` on your path after `cargo install --path .`.

### Offline (Layers 1, 2, 5)

    # 1. Generate a signing keypair. The command prints the public key in hex;
    #    copy it for --subject in step 3.
    attest keygen --out author.key

    # 2. Draft a payload. Any JSON that RFC 8785 can canonicalize.
    echo '{"note":"first attestation"}' > payload.json

    # 3. Sign. This example self-attests, so signer and subject are the same key.
    #    Use --subject-base58 instead if the subject is a Solana-style pubkey.
    attest sign --key author.key \
      --subject <hex-pubkey-from-keygen> \
      --activity-type "https://schemas.example.org/self-report/v1" \
      --payload payload.json \
      --out attestation.json

    # 4. Verify offline. Reconstructs canonical bytes, checks the Ed25519
    #    signature, and confirms SHA-256(payload) == data_hash.
    attest verify attestation.json

    # 5. Issue a single-use disclosure token, then redeem it once.
    attest disclose issue --attestation attestation.json --key author.key --out token.json
    attest disclose redeem --token token.json --attestation attestation.json

    # 6. A second redeem is refused per SPEC §6.3 single-use exhaustion.
    attest disclose redeem --token token.json --attestation attestation.json

Every check has a distinct error class. A tampered payload is rejected as `tampered_payload`. An expired token is rejected as `expired`. A second redeem is rejected as `already_consumed`. Consult SPEC §6.3 for the full list.

### On devnet (Layer 4)

> **One-time operator setup required.** Anchoring to devnet needs a funded fee-payer keypair, a SAS credential naming that key as authority, and a SAS schema declaring the v0.2 receipt layout. Complete the step-by-step walkthrough in **[docs/devnet-setup.md](./docs/devnet-setup.md)** first (about 10 minutes including a faucet airdrop). It ends with you holding a `SAS_CREDENTIAL` pubkey, a `SAS_SCHEMA` pubkey, and a funded fee-payer keypair.

Once setup is complete:

    # Anchor. Writes a sibling file `attestation.anchor-devnet.json` next to
    # attestation.json. Anchoring never mutates the attestation itself; the
    # signed artifact stays immutable.
    attest anchor attestation.json --cluster devnet \
      --fee-payer $FEE_PAYER \
      --credential $SAS_CREDENTIAL \
      --schema $SAS_SCHEMA

    # Check. Discovers all `attestation.anchor-*.json` siblings and confirms
    # each anchor matches the local attestation.
    attest check attestation.json

    # Confirm. Runs verify (Layer 1+2) + check (Layer 4) in one command with
    # a unified pass/fail verdict. This is the "did they send me what they
    # said and is it real?" command for a bundle from a third party.
    attest confirm attestation.json

Anchoring the same attestation to a second cluster writes a second sibling file. Both anchors coexist as durable notarizations of the same signed content:

    attest anchor attestation.json --cluster mainnet-beta \
      --fee-payer $MAINNET_FEE_PAYER \
      --credential $MAINNET_SAS_CREDENTIAL \
      --schema $MAINNET_SAS_SCHEMA

    # A subsequent `attest check attestation.json` now confirms both anchors.

The two-file layout means a full bundle you can hand to a third party is: `attestation.json` (the signed artifact) plus one anchor sibling file per cluster (e.g., `attestation.anchor-devnet.json`, `attestation.anchor-mainnet-beta.json`). Pre-refactor bundles that embedded anchors inside `attestation.json` still verify and check without any migration; the CLI reads legacy embedded anchors as a fallback.

### Conformance

The CLI ships golden vectors under `fixtures/v0.2/vectors.json`. Any conforming implementation MUST reproduce these vectors byte-for-byte:

    attest vectors verify fixtures/v0.2/vectors.json

See [SPEC.md](https://github.com/extol-work/sworn/blob/main/SPEC.md) for what the CLI is implementing against, and [bindings/sas.md](https://github.com/extol-work/sworn/blob/main/bindings/sas.md) for the Solana binding this CLI targets.

## Contributing

Not yet accepting external contributions. The reference implementation is still stabilizing against the specification. Issues welcome for anything that reads incorrectly against SPEC.md.

## License

Apache 2.0. See [LICENSE](./LICENSE).
