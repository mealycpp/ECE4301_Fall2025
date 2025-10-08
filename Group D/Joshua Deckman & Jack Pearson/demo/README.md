The demo requires rust to be installed, as well as `time` (`sudo apt install
time`).

The demo simply repreatedly encrypts a random buffer with CTR encryption mode.
Default size is 256 MiB and default iterations is 20x. So the main instruction
being exercised is `aese`.

The demo can be run by simply executing `./bench.sh`.

This will run hardware-accelerated (HW) and pure-software (SOFT) versions of the demo.

On our Pi, we observe that the demo finishes in 24.14 seconds with HW
acceleration and 59.39 seconds without HW acceleration, meaning the Pi crypto
engine **does indeed reduce runtime by about 50%**.

A video of running the demo is in this directory. Below are the results of the
demo:

```
================= HW =================
(perf unavailable or not permitted; running without perf)
	Command being timed: "target/release/aes_demo_hw --mib 256 --iterations 20 --quiet"
	User time (seconds): 24.14
	System time (seconds): 0.04
	Percent of CPU this job got: 99%
	Elapsed (wall clock) time (h:mm:ss or m:ss): 0:24.20
	Average shared text size (kbytes): 0
	Average unshared data size (kbytes): 0
	Average stack size (kbytes): 0
	Average total size (kbytes): 0
	Maximum resident set size (kbytes): 263728
	Average resident set size (kbytes): 0
	Major (requiring I/O) page faults: 0
	Minor (reclaiming a frame) page faults: 16451
	Voluntary context switches: 1
	Involuntary context switches: 431
	Swaps: 0
	File system inputs: 0
	File system outputs: 0
	Socket messages sent: 0
	Socket messages received: 0
	Signals delivered: 0
	Page size (bytes): 16384
	Exit status: 0

================= SOFT =================
(perf unavailable or not permitted; running without perf)
	Command being timed: "target/release/aes_demo_soft --mib 256 --iterations 20 --quiet"
	User time (seconds): 59.39
	System time (seconds): 0.04
	Percent of CPU this job got: 99%
	Elapsed (wall clock) time (h:mm:ss or m:ss): 0:59.45
	Average shared text size (kbytes): 0
	Average unshared data size (kbytes): 0
	Average stack size (kbytes): 0
	Average total size (kbytes): 0
	Maximum resident set size (kbytes): 263728
	Average resident set size (kbytes): 0
	Major (requiring I/O) page faults: 0
	Minor (reclaiming a frame) page faults: 16451
	Voluntary context switches: 1
	Involuntary context switches: 761
	Swaps: 0
	File system inputs: 0
	File system outputs: 0
	Socket messages sent: 0
	Socket messages received: 0
	Signals delivered: 0
	Page size (bytes): 16384
	Exit status: 0
```
