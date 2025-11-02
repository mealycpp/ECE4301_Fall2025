### Results for Hardware Acceleration ###

    $ grep -m1 -i features /proc/cpuinfo

    Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp


Runtime detection log:

    ARMv8 Crypto Extensions — AES: true, PMULL: true

RSA key exchange time with hardware acceleration: `3973 ms`

RSA key exchange time without hardware acceleration: `4227 ms`
