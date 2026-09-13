use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../../.git/logs/HEAD");
    println!("cargo:rerun-if-changed=../../../.git/packed-refs");
    if let Ok(head) = fs::read_to_string("../../../.git/HEAD")
        && let Some(reference) = head.trim().strip_prefix("ref: ")
    {
        println!("cargo:rerun-if-changed=../../../.git/{reference}");
    }
    println!("cargo:rerun-if-changed=../..");
    println!("cargo:rerun-if-changed=../../../experiments");
    println!("cargo:rerun-if-changed=../../../.dockerignore");
    println!("cargo:rerun-if-changed=../../../Cargo.lock");
    for variable in [
        "SILK_BUILD_GIT_COMMIT",
        "SILK_BUILD_GIT_DIRTY",
        "SILK_BUILD_SOURCE_FINGERPRINT",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    let commit = env::var("SILK_BUILD_GIT_COMMIT").unwrap_or_else(|_| git_commit());
    println!("cargo:rustc-env=GIT_COMMIT={commit}");
    let dirty = env::var("SILK_BUILD_GIT_DIRTY")
        .map(|value| value == "true")
        .unwrap_or_else(|_| git_dirty());
    println!("cargo:rustc-env=GIT_DIRTY={dirty}");
    let source_fingerprint =
        env::var("SILK_BUILD_SOURCE_FINGERPRINT").unwrap_or_else(|_| source_fingerprint());
    println!("cargo:rustc-env=SOURCE_FINGERPRINT={source_fingerprint}");
    let rustc = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=RUSTC_VERSION={rustc}");
    let lock = fs::read("../../../Cargo.lock").unwrap_or_default();
    let digest = hex::encode(crypto_primitives::hash::sha256(&lock));
    println!("cargo:rustc-env=CARGO_LOCK_SHA256={digest}");
}

fn git_commit() -> String {
    if !PathBuf::from("../../../.git").exists() {
        return "unversioned".into();
    }
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| "unknown".into())
}

fn git_dirty() -> bool {
    if !PathBuf::from("../../../.git").exists() {
        return false;
    }
    Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=normal"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_none_or(|output| !output.stdout.is_empty())
}

fn source_fingerprint() -> String {
    let commit = git_code_output(&["rev-parse", "HEAD"]);
    let diff = git_code_output(&["diff", "--binary", "HEAD", "--", "."]);
    let untracked = git_code_output(&[
        "ls-files",
        "--others",
        "--exclude-standard",
        "--full-name",
        "--",
        ".",
    ]);
    let repository_root = String::from_utf8(git_code_output(&["rev-parse", "--show-toplevel"]))
        .map(|value| PathBuf::from(value.trim()))
        .unwrap_or_default();
    let mut source_material = b"silk-source-fingerprint/v2\0".to_vec();
    source_material.extend_from_slice(String::from_utf8_lossy(&commit).trim().as_bytes());
    source_material.push(0);
    source_material.extend_from_slice(&diff);
    for relative in String::from_utf8_lossy(&untracked).lines() {
        source_material.push(0);
        source_material.extend_from_slice(relative.as_bytes());
        source_material.push(0);
        source_material
            .extend_from_slice(&fs::read(repository_root.join(relative)).unwrap_or_default());
    }
    hex::encode(crypto_primitives::hash::sha256(&source_material))
}

fn git_code_output(arguments: &[&str]) -> Vec<u8> {
    if !PathBuf::from("../../../.git").exists() {
        return Vec::new();
    }
    Command::new("git")
        .args(arguments)
        .current_dir("../../..")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| output.stdout)
        .unwrap_or_default()
}
