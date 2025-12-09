# Convert prog.bin -> prog.hex (one 32-bit LE word per line, no @)
from pathlib import Path

b = Path("prog.bin").read_bytes()
# pad to 4-byte multiple
if len(b) % 4:
    b += b'\x00' * (4 - (len(b) % 4))

with open("prog.hex", "w") as f:
    for i in range(0, len(b), 4):
        w = int.from_bytes(b[i:i+4], "little")
        f.write(f"{w:08x}\n")
