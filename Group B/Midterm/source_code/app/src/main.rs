fn main() {
    #[cfg(target_arch = "aarch64")]
    {
        let aes   = std::arch::is_aarch64_feature_detected!("aes");
        let pmull = std::arch::is_aarch64_feature_detected!("pmull");
        println!("ARMv8 Crypto Extensions — AES: {aes}, PMULL: {pmull}");
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        println!("Not on aarch64; skipping ARMv8 CE detection.");
    }
}


