f = open("/dev/hwrng","rb")

while True:
    x = int.from_bytes(f.read(4), "little")
    print(f"{x:08x}")
