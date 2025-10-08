## Steps for Demo

1) Create Python Virtual environment
python -m venv venv

2) Start venv
source venv/bin/activate

3) Download dependencies
sudo apt install -y build-essential linux-headers-$(uname -r) \
    python3 python3-pip python3-matplotlib python3-pandas
pip3 install pandas matplotlib

4) Run the benchmark + plotting script
./run_bench.sh
python3 plot.py


This demo evaluates the **Raspberry Pi 5 hardware crypto engine** (AF_ALG interface) against a **pure software AES-128-CBC** implementation.


### ⚙️ What the benchmark does
1. Encrypts and decrypts random buffers of varying **chunk sizes** (4 KB – 1 MB).  
2. Measures:
   - **Throughput** (MB/s) — how fast data is processed.
   - **CPU time** (ms) — processor time consumed per test.
3. Runs both **encryption (`enc`)** and **decryption (`dec`)** for multiple total data sizes (64 MB, 128 MB, 256 MB).  
4. Saves results to `results.csv` and generates plots showing throughput scaling and CPU efficiency.

