# Hash Benchmark (`hash_benchmark`)
### Automated benchmarking that systematically tests all five hash algorithms across 10 different input sizes (16B to 16MB) and three core configurations (1, 2, 4 cores), totaling 150 test combinations. Exports results to (`hash_benchmark_results.csv`)
#### Build

    cd hash_benchmark
    RUSTFLAGS="-C target-cpu=native" cargo build --release

#### Run

    ./target/release/hash_benchmark
