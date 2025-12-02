f = open("/dev/hwrng","rb")
out = open("trng_output.txt","w")

for _ in range(10000):
    x = int.from_bytes(f.read(4), "little")
    out.write(f"{x:08x}\n")

out.close()
print("Saved 10000 values to trng_output.txt")
