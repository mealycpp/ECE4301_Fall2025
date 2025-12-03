# ECE4301-Midterm2 #

This project showcases some ways to use the TRNG that is built into the Raspberry Pi 5.

# Demo #

To run a simple demonstration of the Pi's TRNG, simply run `demo.sh`:

```sh
$ ./demo.sh
```

At the end of the demo, a raw output file (`hwrng.out`) will be produced from the datastream of 
the TRNG. You can run post-processing on this file by running the included Python 
script:

```sh
$ python3 to_csv.py
```

This script will take the random data from the output file and convert it into 
a set of two-dimensional points stored in CSV format. Simply follow the 
interactive prompts to specify the source random data, the output CSV file, 
and the number of points you would like to be made.

Example output:

```
$ python3 to_csv.py 

Enter number of points to acquire: 1024
Enter source file: hwrng.out
Enter csv file to which to store data: random_points.csv
Saved 1024 points.
```

If you would like to read directly from the TRNG, simply read from 
`/dev/hwrng`.

Here are 256 bytes of output on our Pi 5:

```
$ head -c 256 /dev/hwrng | hexdump
0000000 9f95 d130 61ab ef18 6ddf d844 bcb4 f542
0000010 4d4b 4f66 f5e2 baf1 a39e e458 779f cc13
0000020 21b9 95d7 7131 4479 222a 33d5 e18f c9c7
0000030 b6e8 6f93 83d3 9fc8 499c 03d2 db38 f859
0000040 96a9 e87c eda6 51aa 5d97 9209 e93f 3d35
0000050 f70e 7654 0b0c 4f05 471a 4de6 43d8 2e93
0000060 79a9 2767 e377 9b85 55e3 25e7 283b 2418
0000070 6bce 86ab 7c84 3ae1 5bdf b9bd 34c5 6d9d
0000080 8126 2e26 46f4 5464 dbf1 8e39 adec 2b7d
0000090 9009 f9a3 22f1 41cc 382c b852 0767 583b
00000a0 99bd 84a5 fa3b 44af 599f 409d a634 b9d3
00000b0 d4b6 e6d4 b11b fbba d5a4 cb06 0274 f634
00000c0 e6b0 9b21 1662 b563 76a1 65f2 076d 33f0
00000d0 b34a debb 8340 3e5c 9701 d654 9b1f aadb
00000e0 48ba fb77 693c 74e0 771e 4879 6f63 334c
00000f0 87b9 1dde a98a 6f35 aae0 af58 5be6 dc7f
0000100
```

# Mechanism

The exact underlying hardware for the TRNG can be found by grepping the active device
tree for mentions of `rng`:

```
$ find /sys/firmware/devicetree/base/ -iname '*rng*'
/sys/firmware/devicetree/base/soc@107c000000/rng@7d208000
```

Inspecting that node reveals there is one TRNG available on the Raspberry Pi
5, the RNG200 from Broadcom.

```
$ cat /sys/firmware/devicetree/base/soc@107c000000/rng@7d208000/compatible
brcm,bcm2711-rng200
```

Grepping the Linux source for the device string lets us find the driver:

```
$ grep -r 'brcm,bcm2711-rng200' drivers/
drivers/char/hw_random/iproc-rng200.c:	{ .compatible = "brcm,bcm2711-rng200", },
```


That driver has this private data indicating it is a memory-mapped device:

```
struct iproc_rng200_dev {
	struct hwrng rng;
	void __iomem *base;
};
```

Details regarding the entropy source are scarce. However, Krzysztof
Kozlowski gives a hint on LKML in 2020:

```
https://lkml.org/lkml/2020/5/20/567
> the TRNG block generates random data from thermal noise
```
