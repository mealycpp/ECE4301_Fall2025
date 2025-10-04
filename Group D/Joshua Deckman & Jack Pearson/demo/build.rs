fn main() {
    // Silence 'unexpected cfg' warnings for these custom toggles.
    println!("cargo::rustc-check-cfg=cfg(aes_force_soft)");
    println!("cargo::rustc-check-cfg=cfg(aes_armv8)");
}

