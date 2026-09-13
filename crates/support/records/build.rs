fn main() {
    let output = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .unwrap();
    println!(
        "cargo:rustc-env=RUSTC_VERSION={}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
}
