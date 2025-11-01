CC=gcc
CFLAGS=-O3 -Wall -Wextra -march=armv8-a -mtune=cortex-a76
LDFLAGS=

OBJS=bench.o aes_soft.o af_alg_aes.o

all: bench

bench: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

bench.o: bench.c aes_soft.h
aes_soft.o: aes_soft.c aes_soft.h
af_alg_aes.o: af_alg_aes.c

clean:
	rm -f bench *.o *.csv *.png
