**RUST Commands:**
Remove excess files:
cargo clean
Compile and Build:
cargo build
Unit Test Runs:
cargo test -- --nocapture


**Verify Crypto-Engine Usage**
cargo run --bin rpi-secure-stream -- --print-config




/rpi-secure-stream                   Rust Crate Root
│
├── Cargo.toml                       Dependencies and build config
│
├── /src                             Source Code
│   │
│   ├── /crypto                      Cryptographic modules
│   │   ├── ecdh.rs                  Elliptic-Curve Diffie–Hellman + HKDF
│   │   ├── rsa_kem.rs               RSA-OAEP Key Encapsulation Mechanism
│   │   └── mod.rs                   Module declarations
│   │
│   ├── /bin                         Standalone benchmark executables
│   │   ├── bench_kex.rs             RSA & ECDH key-exchange benchmark
│   │   └── bench_aesgcm.rs          AES-128-GCM throughput benchmark (CE on/off proof)
│   │
│   └── main.rs                      Main entrypoint (CLI + runtime config)
│
├── /setup                           Raspberry Pi setup scripts
│   ├── leader_pi_setup.sh           Setup dependencies for Leader KEM RPi5 node
│   ├── listener_pi_setup.sh         Setup dependencies for Listener RPi5 nodes
│   ├── leader_demo.sh               Example run/demo script for leader node
│   └── listener_demo.sh             Example run/demo script for listener nodes
│
└── README.md                        (this file)
