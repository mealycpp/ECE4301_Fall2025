To evaluate throughput and latency of each instruction, there are essentially
two datapoints needed:

- The number of cycles per instruction in a chain of **independent**
  instructions to measure **throughput**

- The number of cycles per instruction in a chain of **dependent**
  instructions to measure **latency**

Then one can also examine the execution time of each variation chain of
instructions.

Our benchmark suite depends on `perf` and `jq`. It is located in the
`benchmarks` subdirectory and you can re-create the report by running `make`
as superuser (for perf privileges).

At the bottom of this file is the report produced on our pi 5.

We find that most instructions have a latency of ~2.4 cycles per instruction.
All of these instructions get *no benefit* from pipelining, demonstrated by
the fact that no speedup is observed for these instructions in the throughput
benchmark in contrast with the latency benchmark.

Some instructions have a latency of ~4.1 cycles per instruction rather than
~2.4. These slower instructions get *some benefit* from pipelining, with the
average cycles per instruction being reduced to ~2.4 again in the throughput
benchmark.

These slower, pipelined instructions are `sha1c`, `sha1m`, `sha1p`,
`sha256h2`, and `sha256h`.

# Main Report using 1000000 instructions for each benchmark

| benchmark | cycles/instr | total execution time |
| --------- | ------------ | -------------------- |
|`aesd-latency`| 2.449 | 1.152167 msec |
|`aesd-throughput`| 2.429 | 1.129257 msec |
|`aese-latency`| 2.447 | 1.151934 msec |
|`aese-throughput`| 2.441 | 1.136245 msec |
|`aesimc-latency`| 2.450 | 1.149506 msec |
|`aesimc-throughput`| 2.439 | 1.137158 msec |
|`aesmc-latency`| 2.448 | 1.145579 msec |
|`aesmc-throughput`| 2.429 | 1.136596 msec |
|`pmull2-latency`| 2.434 | 1.137877 msec |
|`pmull2-throughput`| 2.427 | 1.129004 msec |
|`pmull-latency`| 2.449 | 1.150671 msec |
|`pmull-throughput`| 2.441 | 1.147328 msec |
|`sha1c-latency`| 4.165 | 1.867643 msec |
|`sha1c-throughput`| 2.438 | 1.147495 msec |
|`sha1h-latency`| 2.447 | 1.145588 msec |
|`sha1h-throughput`| 2.429 | 1.133902 msec |
|`sha1m-latency`| 4.163 | 1.871506 msec |
|`sha1m-throughput`| 2.442 | 1.145644 msec |
|`sha1p-latency`| 4.160 | 1.864843 msec |
|`sha1p-throughput`| 2.439 | 1.150520 msec |
|`sha1su0-latency`| 2.443 | 1.149900 msec |
|`sha1su0-throughput`| 2.432 | 1.136292 msec |
|`sha1su1-latency`| 2.449 | 1.147486 msec |
|`sha1su1-throughput`| 2.426 | 1.133552 msec |
|`sha256h2-latency`| 4.155 | 1.860340 msec |
|`sha256h2-throughput`| 2.446 | 1.147656 msec |
|`sha256h-latency`| 4.163 | 1.866262 msec |
|`sha256h-throughput`| 2.441 | 1.143183 msec |
|`sha256su0-latency`| 2.230 | 1.313721 msec |
|`sha256su0-throughput`| 2.436 | 1.146136 msec |
|`sha256su1-latency`| 2.460 | 1.147861 msec |
|`sha256su1-throughput`| 2.436 | 1.139963 msec |

