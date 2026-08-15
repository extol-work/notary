#!/usr/bin/env python3
"""Decode a SAS attestation PDA account on Solana devnet.

Fetches the raw account bytes via getAccountInfo and prints the fields
per the SAS on-chain layout. Independent of the notary CLI: any adopter
who wants to verify what is actually on-chain without trusting the CLI
can run this and read the bytes for themselves.

No external dependencies. Python 3 stdlib only.

    python3 scripts/decode-attestation.py <ATTESTATION_PDA>

The PDA is the "attestation PDA:" address printed by `attest anchor` or
`attest check`. To target a different cluster, override RPC_URL below.
"""
import base64
import json
import struct
import sys
import urllib.request

RPC_URL = "https://api.devnet.solana.com"

# Solana base58 alphabet (the Bitcoin variant).
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    """Encode bytes as base58 the way Solana does."""
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = BASE58_ALPHABET[r] + out
    # Preserve leading zero bytes as leading '1' chars.
    for byte in data:
        if byte == 0:
            out = "1" + out
        else:
            break
    return out


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <ATTESTATION_PDA>")
    pda = sys.argv[1]

    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [pda, {"encoding": "base64"}],
    }).encode()
    req = urllib.request.Request(
        RPC_URL,
        data=body,
        headers={"Content-Type": "application/json"},
    )
    resp = json.loads(urllib.request.urlopen(req).read())
    value = resp["result"]["value"]
    if value is None:
        sys.exit(f"account {pda} not found at {RPC_URL}")

    owner = value["owner"]
    lamports = value["lamports"]
    data = base64.b64decode(value["data"][0])
    print(f"pda:                {pda}")
    print(f"owner:              {owner}")
    print(f"lamports:           {lamports}")
    print(f"data size:          {len(data)} bytes")
    print()

    # Sanity checks before decoding: must be owned by SAS and large enough
    # to hold at least the fixed prefix + a receipt of any size.
    SAS_PROGRAM = "22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG"
    if owner != SAS_PROGRAM:
        sys.exit(f"account is not owned by SAS ({SAS_PROGRAM}); refusing to decode")
    if len(data) < 173:
        sys.exit(f"account data is only {len(data)} bytes; too small to be a SAS attestation")

    # SAS attestation account layout (see notary/src/anchor.rs docstring):
    #   [0..1]   discriminator
    #   [1..33]  nonce                (32 bytes = SHA-256(canonical_bytes))
    #   [33..65] credential           (32-byte pubkey)
    #   [65..97] schema               (32-byte pubkey)
    #   [97..101] data length prefix  (u32 LE, always 46 for v0.2)
    #   [101..101+len] data section   (46 bytes for v0.2)
    #   [.. +32] signer               (32-byte credential-authority pubkey)
    #   [.. +8]  expiry               (i64 LE, 0 = never)
    #   [.. +32] token account        (32 bytes, all zeros for non-tokenized)
    disc = data[0]
    nonce = data[1:33]
    credential = data[33:65]
    schema = data[65:97]
    data_len = struct.unpack("<I", data[97:101])[0]
    receipt = data[101:101 + data_len]
    signer = data[101 + data_len:101 + data_len + 32]
    expiry = struct.unpack("<q", data[101 + data_len + 32:101 + data_len + 40])[0]
    token_account = data[101 + data_len + 40:101 + data_len + 72]

    print(f"discriminator:      {disc}")
    print(f"nonce (base58):     {base58_encode(nonce)}")
    print(f"nonce (hex):        {nonce.hex()}")
    print(f"credential:         {base58_encode(credential)}")
    print(f"schema:             {base58_encode(schema)}")
    layout_label = "v0.2 receipt" if data_len == 46 else "unknown layout"
    print(f"data_len prefix:    {data_len} ({layout_label})")
    print()

    # v0.2 receipt layout:
    #   [0..2]  spec_version              (u16 LE, always 3 for v0.2)
    #   [2..6]  attestation_hash prefix   (u32 LE, always 32)
    #   [6..38] attestation_hash          (32 bytes)
    #   [38..46] signer_asserted_at       (i64 LE)
    att_hash = None
    if data_len == 46:
        spec_version = struct.unpack("<H", receipt[0:2])[0]
        hash_len = struct.unpack("<I", receipt[2:6])[0]
        att_hash = receipt[6:6 + hash_len]
        signer_asserted_at = struct.unpack("<q", receipt[6 + hash_len:14 + hash_len])[0]
        print(f"spec_version:       {spec_version}")
        print(f"attestation_hash:   {att_hash.hex()}")
        print(f"signer_asserted_at: {signer_asserted_at} (Unix seconds)")
        print()

    print(f"signer:             {base58_encode(signer)}")
    expiry_note = "never" if expiry == 0 else "Unix seconds"
    print(f"expiry:             {expiry} ({expiry_note})")
    print(f"token_account:      {base58_encode(token_account)}")

    if att_hash is not None:
        print()
        print(f"nonce == attestation_hash?  {nonce == att_hash}")
        print("(Both are SHA-256 of the 248-byte canonical sequence. The")
        print(" duplication is deliberate: the PDA seed is opaque with")
        print(" respect to every identifying field, which is what enforces")
        print(" SPEC §5.1 non-walkability.)")


if __name__ == "__main__":
    main()
