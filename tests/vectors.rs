//! Integration test: the shipped `fixtures/v0.2/vectors.json` file MUST pass
//! `attest vectors verify` byte-for-byte.
//!
//! This catches drift between the emit path (which can be freely edited to
//! add new vectors) and the shipped file (which any conforming implementation
//! reads as ground truth). If someone edits the emit path without regenerating
//! the file, this test fails loud.

use std::path::PathBuf;
use std::process::Command;

fn attest_bin() -> PathBuf {
    // Cargo puts the built binary at target/{profile}/attest.
    // env!("CARGO_BIN_EXE_attest") is the standard cargo integration-test macro.
    PathBuf::from(env!("CARGO_BIN_EXE_attest"))
}

fn fixture_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("fixtures");
    p.push("v0.2");
    p.push("vectors.json");
    p
}

#[test]
fn shipped_v02_vectors_verify_byte_for_byte() {
    let output = Command::new(attest_bin())
        .arg("vectors")
        .arg("verify")
        .arg(fixture_path())
        .output()
        .expect("run `attest vectors verify`");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "attest vectors verify failed on shipped fixture.\n\
         stdout:\n{stdout}\n\
         stderr:\n{stderr}\n\
         If the emit path changed, regenerate:\n  \
         cargo run -- vectors emit --out fixtures/v0.2/vectors.json"
    );

    // Sanity check on output: should mention PASS and all 5 vectors.
    assert!(stdout.contains("PASS: 5 / 5"), "stdout:\n{stdout}");
}

#[test]
fn emit_output_matches_shipped_fixture() {
    // Emit to a temp path and byte-compare against the shipped fixture.
    // Drift between the two indicates the fixture was hand-edited or the
    // emit path was changed without a regen.
    let tmp = std::env::temp_dir().join(format!(
        "notary-test-vectors-{}.json",
        std::process::id()
    ));

    let status = Command::new(attest_bin())
        .arg("vectors")
        .arg("emit")
        .arg("--out")
        .arg(&tmp)
        .status()
        .expect("run `attest vectors emit`");
    assert!(status.success(), "vectors emit failed");

    let shipped = std::fs::read_to_string(fixture_path()).expect("read shipped fixture");
    let regenerated = std::fs::read_to_string(&tmp).expect("read regenerated");
    let _ = std::fs::remove_file(&tmp);

    // Parse both to serde_json::Value to normalize any harmless whitespace/
    // key-order differences (there shouldn't be any but this is defense-in-depth).
    let shipped_val: serde_json::Value = serde_json::from_str(&shipped).unwrap();
    let regenerated_val: serde_json::Value = serde_json::from_str(&regenerated).unwrap();

    assert_eq!(
        shipped_val, regenerated_val,
        "shipped fixture drifted from emit output. Regenerate with:\n  \
         cargo run -- vectors emit --out fixtures/v0.2/vectors.json"
    );
}
