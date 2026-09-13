fn main() {
    println!("cargo:rustc-check-cfg=cfg(silk_mldsa_native)");
    println!("cargo:rerun-if-changed=vendor");
    println!("cargo:rerun-if-changed=adapter.c");
    if std::env::var_os("CARGO_FEATURE_NATIVE").is_none()
        || std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return;
    }
    let native = "vendor/mldsa-native/mldsa";
    cc::Build::new()
        .include(native)
        .define("MLD_CONFIG_PARAMETER_SET", "65")
        .define("MLD_CONFIG_NAMESPACE_PREFIX", "silk_native65")
        .define("MLD_CONFIG_NO_RANDOMIZED_API", None)
        .define("MLD_CONFIG_USE_NATIVE_BACKEND_ARITH", None)
        .define("MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202", None)
        // Clang's assembler preprocessor omits __AVX2__ even with -mavx2.
        // Select the same backend for C and assembly; native entry points
        // still require AVX2 and POPCNT at runtime.
        .define("MLD_SYS_X86_64_AVX2", Some(""))
        .flag("-mavx2")
        .flag("-mpopcnt")
        .flag("-std=c99")
        .file(format!("{native}/mldsa_native.c"))
        .file(format!("{native}/mldsa_native_asm.S"))
        .file("adapter.c")
        .compile("silk_mldsa_native65");
    println!("cargo:rustc-cfg=silk_mldsa_native");
}
