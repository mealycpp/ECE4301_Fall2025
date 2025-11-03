### Hardware Acceleration ###

    $ grep -m1 -i features /proc/cpuinfo

    Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp


Runtime detection log:

    ARMv8 Crypto Extensions — AES: enabled, PMULL: enabled

Key exchange with hardware acceleration: `3995 ms`

Key exchange without hardware acceleration: `4128 ms`
