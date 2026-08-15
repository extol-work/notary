# Devnet walkthrough

Anchoring an attestation to Solana devnet requires one-time operator setup:
a funded fee-payer keypair, an on-chain SAS credential naming that key as
authority, and an on-chain SAS schema declaring the v0.2 receipt layout.

Once complete you have a working end-to-end devnet notarization pipeline
under your own key. Total wall time: about 10 minutes including a faucet
airdrop. Total devnet SOL: about 0.005 for provisioning, plus about 0.001
per anchor thereafter.

Every command below assumes you have `attest` on your path (see the
repository README for install instructions).

---

## 1. Generate a fee-payer keypair

The fee-payer pays for on-chain rent and transaction fees. It is also the
credential authority: only keys authorized under this credential can create
attestations against it.

    attest admin keygen-fee-payer --out keys/devnet-fee-payer.json

Expected output:

    wrote devnet fee-payer keypair: keys/devnet-fee-payer.json
    pubkey (base58):                <YOUR_FEE_PAYER_PUBKEY>

Copy the pubkey. You will fund it next and reference it in every
subsequent command. The file is written with owner-read-only permissions;
treat the private seed as sensitive even though this is devnet.

The default output path lives inside a `keys/` directory that is gitignored
by default. If you prefer a different path, pass `--out` explicitly and
make sure your `.gitignore` blocks it.

## 2. Fund the fee-payer

Any of the standard devnet airdrop sources works. One SOL is more than
enough for provisioning plus hundreds of anchor operations.

    # Via the solana CLI if you have it installed
    solana airdrop 1 <YOUR_FEE_PAYER_PUBKEY> --url devnet

    # Or paste the pubkey into https://faucet.solana.com (pick devnet)

Confirm the balance landed. The notary CLI can query it without needing
the solana CLI:

    attest admin balance

Expected output includes a nonzero `balance:` line. If it prints zero or
returns an error, the airdrop has not yet finalized; wait a few seconds
and retry.

## 3. Provision your SAS credential

The credential is a SAS-owned PDA that names your fee-payer as the sole
authorized signer. One-time per environment; idempotent on re-run.

    attest admin provision-credential

Expected output ends with:

    credential created.
    tx:                    <TX_SIGNATURE>
    SAS_CREDENTIAL:        <YOUR_CREDENTIAL_PDA>

Copy `SAS_CREDENTIAL`. You will pass it to `attest anchor` as
`--credential`.

If the credential already exists (you have run this before), the command
prints "credential already exists on devnet. Nothing to do." and exits
without spending SOL. Safe to re-run whenever unsure.

## 4. Provision your SAS schema

The schema declares the receipt layout: `spec_version (u16 LE) ||
attestation_hash (VecU8 of 32) || signer_asserted_at (i64 LE)`. On-chain
size is 46 bytes.

    attest admin provision-schema

Expected output ends with:

    schema created.
    tx:                    <TX_SIGNATURE>
    SAS_SCHEMA:            <YOUR_SCHEMA_PDA>

Copy `SAS_SCHEMA`. You will pass it to `attest anchor` as `--schema`.

Same idempotency: safe to re-run.

## 5. Save your addresses

Both PDAs are derived deterministically from your fee-payer authority, so
you can always re-derive them by re-running provision steps. But it is
easier to save them somewhere convenient than to re-derive every time. A
minimal `.env`-style file in your workspace works:

    # ~/.notary-devnet
    FEE_PAYER=keys/devnet-fee-payer.json
    SAS_CREDENTIAL=<YOUR_CREDENTIAL_PDA>
    SAS_SCHEMA=<YOUR_SCHEMA_PDA>

Or export them in your shell:

    export FEE_PAYER=keys/devnet-fee-payer.json
    export SAS_CREDENTIAL=<YOUR_CREDENTIAL_PDA>
    export SAS_SCHEMA=<YOUR_SCHEMA_PDA>

The CLI does not currently read these env vars; substitute them into
command arguments. Env var integration is a small future ergonomics
improvement.

**Setup complete.** You can return to the main README's "On devnet"
section for a compact anchor + check + confirm sequence, or continue
below for a more detailed walkthrough of the Layer 4 test with
per-command explanations.

## 6. Anchor a test attestation

Sign an attestation offline first (see the "Offline" section of the main
README if you have not already), then anchor it:

    attest anchor attestation.json --cluster devnet \
      --fee-payer $FEE_PAYER \
      --credential $SAS_CREDENTIAL \
      --schema $SAS_SCHEMA

Expected output includes an `attestation PDA:` line, a `tx:` line, an
`anchored at:` line with a slot number and block time, and a final
`wrote anchor file: attestation.anchor-devnet.json` line.

The anchor record lives in a **new sibling file** next to your
attestation. For an input named `attestation.json` anchored to devnet,
that file is `attestation.anchor-devnet.json`. The `attestation.json`
itself is never modified after `attest sign`: it is a signed artifact,
and signed artifacts stay immutable. Anchoring to a second cluster later
would write a second sibling file (`attestation.anchor-mainnet-beta.json`)
without touching either the attestation or the devnet anchor.

## 7. Verify the anchor

Read the on-chain state back and confirm it matches your local files:

    attest check attestation.json

`check` discovers every sibling anchor file next to the attestation
(e.g., `attestation.anchor-devnet.json`) and checks each against the
substrate. Expected: `status: MATCHES local record` and `PASS: 1/1
anchor(s) match the local record`.

### When to reach for `check` vs `verify` vs `confirm`

Three separate commands, three separate questions:

- **`attest verify attestation.json`** offline. "Is the signature
  valid and does the payload I hold match the `data_hash` that got
  signed?" Catches payload tampering. Does not touch the network.
- **`attest check attestation.json`** online, Layer 4. "Was this
  attestation's hash durably notarized on the substrate?" Catches
  missing or mismatched anchors. Does not touch the payload.
- **`attest confirm attestation.json`** runs both with a unified
  verdict. "Did they send me what they said and is it real?"

The split matters because the on-chain anchor commits only to the hash
of the canonical bytes, not to the payload. A tampered payload will
still `check` cleanly (the on-chain hash is unchanged) but will fail
`verify` (the recomputed payload hash no longer matches `data_hash`).
Bundle recipients should default to `confirm`.

    attest confirm attestation.json

## 8. Cleanup and next steps

Nothing to clean up. The credential and schema you created stay on devnet
indefinitely and serve every future anchor operation under this
fee-payer.

With `attest confirm` passing above, you have exercised the full
Attestation Notary stack: Layer 1+2 (offline sign + verify, covered in
the main README's "Offline" section), Layer 4 (on-chain notarization
via `anchor` + `check`), and Layer 5 (disclosure tokens, also covered
in the main README). This is what the specification defines end-to-end.

Anchoring the same attestation to a second cluster works with the same
command and a different `--cluster`; the resulting sibling file coexists
with the devnet one and both anchors notarize the same signed
attestation. Meaningful only once mainnet is available; the notary CLI
treats `mainnet-beta` as unprovisioned until an operator has walked
through this same sequence against it.

---

## Troubleshooting

**"Invalid account owner" (custom program error 0x1):** you passed a
plain wallet pubkey where the CLI expected a SAS-owned credential or
schema PDA. Re-check `--credential` and `--schema`: they should be the
PDA addresses printed by steps 3 and 4, not your fee-payer pubkey.

**"custom program error 0x5":** unauthorized signer. Your fee-payer key
is not in the credential's authorized_signers list. Most common cause:
you ran `attest anchor` with a fee-payer path different from the one you
used in step 3. Re-run with the fee-payer that provisioned the
credential.

**"zero balance" from `attest admin balance`:** the airdrop has not yet
finalized. Wait a few seconds and retry. If it persists past a minute,
the faucet may be rate-limited or your pubkey may be a typo.

**Rustup downloads a fresh toolchain on first `cargo install`:** expected.
The repo pins its rustc version via `rust-toolchain.toml` so builds are
reproducible regardless of what you have as your global default. The
one-time download is about 100 MB.

## Operators of other deployments

The steps above describe a single-operator single-signer setup. SAS
supports multi-signer credentials (Cortex uses this for KMS-backed
signing), differently-named credentials or schemas, and mainnet
deployment. The CLI's `--credential`, `--schema`, and `--fee-payer`
flags accept any operator-provided values; the provisioning subcommands
create fresh PDAs under whatever fee-payer you point them at. Rotating
authorized signers requires SAS `ChangeAuthorizedSigners` (instruction
3), which the CLI does not currently wrap; the underlying tx can be
constructed via any Solana client or is easy to add as a follow-on
subcommand if needed.
