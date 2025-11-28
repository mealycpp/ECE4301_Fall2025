# ECE 4301 – Midterm #2  
## True Random Number Generator (TRNG) on Raspberry Pi Crypto Engine

This project implements and demonstrates a **True Random Number Generator (TRNG)** using the Raspberry Pi’s hardware crypto engine, accessed via the Linux **`/dev/hwrng`** interface.

The goals are:

- To read true random data from the Raspberry Pi hardware TRNG.
- To demonstrate basic functionality with a simple demo script.
- To perform simple statistical checks (monobit test, histogram) to provide evidence that the TRNG output behaves like random data.
- To document the setup and usage so the project can be reproduced and graded easily.

---

## 1. Hardware & Software Requirements

**Hardware:**

- Raspberry Pi with hardware RNG enabled  
  (e.g., Raspberry Pi 4 or compatible board used in ECE 4301)

**Software:**

- Raspberry Pi OS (Linux)
- Python 3
- `matplotlib` for plotting

To install Python + `matplotlib` (if needed):

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-matplotlib
