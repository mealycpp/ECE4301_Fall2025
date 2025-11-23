#command linds use to build SHA soft and accel
cd ~/quiz-2

cargo build --release --bin soft  --features soft
cargo build --release --bin accel --features accel

mkdir -p out

taskset -c 3 ./target/release/soft  \
  --algo sha1   --pin-core 3 bench --sizes 1024,8192,65536,1048576 --trials 5 \
  --csv out/sha1_soft.csv

taskset -c 3 ./target/release/soft  \
  --algo sha256 --pin-core 3 bench --sizes 1024,8192,65536,1048576 --trials 5 \
  --csv out/sha256_soft.csv

taskset -c 3 ./target/release/accel \
  --algo sha1   --pin-core 3 bench --sizes 1024,8192,65536,1048576 --trials 5 \
  --csv out/sha1_accel.csv

taskset -c 3 ./target/release/accel \
  --algo sha256 --pin-core 3 bench --sizes 1024,8192,65536,1048576 --trials 5 \
  --csv out/sha256_accel.csv

./scripts/engine_baselines.sh

python3 scripts/make_engine_csv.py

python3 scripts/plots.py

./scripts/capture_and_hash.sh