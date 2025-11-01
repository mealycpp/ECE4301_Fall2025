cmd process to compile and build

cargo clean
cargo build
cargo test -- --nocapture





File Structure

/rpi-secure-stream              Rust Crate
 | /src                         Codebase Directory
    | /bin                      Directory for non-main executables
        | bench_kex.rs          RSA & RCDH benchmark test
        | 
    | /crypto                   Codebase for functions
        | ecdh.rs               Elliptic-Curve Deffie-Helman
        | mod.rs             
        | rsa_kem.rs            RSA KEM Algorithm
    | main.rs                   Main driver code
/setup
 | leader_demo.sh               ??   
 | leader_pi_setup.sh           Utilize to setup dependencies for LeaderKEM RPi5   
 | listener_demo.sh             ??
 | listener_pi_setup.sh         Utilize to setup dependencies for listener RPi5
