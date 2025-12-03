// This file is Copyright (c) 2013-2014 Sebastien Bourdeauducq <sb@m-labs.hk>
// This file is Copyright (c) 2014-2019 Florent Kermarrec <florent@enjoy-digital.fr>
// This file is Copyright (c) 2015 Yann Sionneau <ys@m-labs.hk>
// This file is Copyright (c) 2015 whitequark <whitequark@whitequark.org>
// This file is Copyright (c) 2019 Ambroz Bizjak <ambrop7@gmail.com>
// This file is Copyright (c) 2019 Caleb Jamison <cbjamo@gmail.com>
// This file is Copyright (c) 2018 Dolu1990 <charles.papon.90@gmail.com>
// This file is Copyright (c) 2018 Felix Held <felix-github@felixheld.de>
// This file is Copyright (c) 2019 Gabriel L. Somlo <gsomlo@gmail.com>
// This file is Copyright (c) 2018 Jean-François Nguyen <jf@lambdaconcept.fr>
// This file is Copyright (c) 2018 Sergiusz Bazanski <q3k@q3k.org>
// This file is Copyright (c) 2016 Tim 'mithro' Ansell <mithro@mithis.com>
// This file is Copyright (c) 2020 Franck Jullien <franck.jullien@gmail.com>
// This file is Copyright (c) 2020 Antmicro <www.antmicro.com>

// License: BSD

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <system.h>
#include <irq.h>

#include "boot.h"
#include "readline.h"
#include "helpers.h"
#include "command.h"

#include <generated/csr.h>
#include <generated/soc.h>
#include <generated/mem.h>
#include <generated/git.h>

#include <libbase/console.h>
#include <libbase/crc.h>
#include <libbase/memtest.h>

#include <libbase/spiflash.h>
#include <libbase/uart.h>
#include <libbase/i2c.h>
#include <libbase/hyperram.h>

#include <liblitedram/sdram.h>
#include <liblitedram/utils.h>

#include <libliteeth/udp.h>
#include <libliteeth/mdio.h>

#include <liblitespi/spiflash.h>
#include <liblitespi/spiram.h>

#include <liblitesdcard/sdcard.h>
#include <liblitesata/sata.h>


#include <stdint.h>

/*---------------------------------------------------------------------*/
/* Simple timing using LiteX timer0 (down-counter)                     */
/*---------------------------------------------------------------------*/
static uint32_t get_timer0_ticks(void)
{
#ifdef CSR_TIMER0_BASE
    /* One-time initialization: set up a free-running down counter. */
    static int initialized = 0;
    if (!initialized) {
        timer0_en_write(0);
        timer0_load_write(0xffffffff);
        timer0_reload_write(0xffffffff);
        timer0_en_write(1);
        initialized = 1;
    }

    /* Latch current value into VALUE register and read it. */
    timer0_update_value_write(1);
    return timer0_value_read();
#else
    return 0;
#endif
}


/*---------------------------------------------------------------------*/
/* Pretty-print timing: ticks + milliseconds                           */
/*---------------------------------------------------------------------*/
static void print_time_ticks_ms(uint32_t elapsed_ticks)
{
#ifdef CSR_TIMER0_BASE
    uint64_t ticks = (uint64_t)elapsed_ticks;
    uint64_t freq  = (uint64_t)CONFIG_CLOCK_FREQUENCY;   /* Hz */
    uint64_t ms    = (ticks * 1000ULL) / freq;

    printf("[BIOS] time       : %lu timer ticks (%lu ms)\n",
           (unsigned long)ticks, (unsigned long)ms);
#else
    (void)elapsed_ticks;
    printf("[BIOS] time       : timer unavailable\n");
#endif
}


// ---------------------------------------------------------------------
// RSA / ECC benchmark hooks for Tera Term
// ---------------------------------------------------------------------

/*---------------------------------------------------------------------*/
/* RSA benchmark: simplified modular exponentiation workload           */
/*---------------------------------------------------------------------*/
static uint32_t modexp32(uint32_t base, uint32_t exp, uint32_t mod)
{
    uint64_t result = 1;
    uint64_t b      = base % mod;

    while (exp) {
        if (exp & 1)
            result = (result * b) % mod;
        b = (b * b) % mod;
        exp >>= 1;
    }
    return (uint32_t)result;
}

void rsa_bench(void)
{
    printf("\n[BIOS] RSA benchmark starting...\n");

    const uint32_t base = 65537u;
    const uint32_t mod  = 4294967291u;
    const uint32_t exp  = 0xf1234567u;

    const int iterations = 400;

    uint32_t t_start = get_timer0_ticks();

    uint32_t acc = 0;
    for (int i = 0; i < iterations; i++) {
        uint32_t e = exp ^ (uint32_t)i;
        acc ^= modexp32(base, e, mod);
    }

    uint32_t t_end    = get_timer0_ticks();
    uint32_t elapsed  = t_start - t_end;

    printf("[BIOS] RSA benchmark complete.\n");
    printf("[BIOS] iterations : %d\n", iterations);
    printf("[BIOS] checksum   : 0x%08x\n", acc);
    print_time_ticks_ms(elapsed);
}

/*---------------------------------------------------------------------*/
/* ECC benchmark: simplified scalar multiplication-style workload      */
/*---------------------------------------------------------------------*/
typedef struct {
    uint32_t x;
    uint32_t y;
} point_t;

static void point_double(point_t *P, uint32_t mod)
{
    uint64_t x = P->x;
    uint64_t y = P->y;

    x = (x * x + 3u * y + 7u) % mod;
    y = (y * y + 5u * x + 11u) % mod;

    P->x = (uint32_t)x;
    P->y = (uint32_t)y;
}

static void point_add(point_t *P, const point_t *Q, uint32_t mod)
{
    uint64_t x = P->x + Q->x;
    uint64_t y = P->y + Q->y;

    x = (x * 17u + y * 19u + 13u) % mod;
    y = (y * 23u + x * 29u + 31u) % mod;

    P->x = (uint32_t)x;
    P->y = (uint32_t)y;
}

static void ecc_scalar(point_t *R, uint32_t k, uint32_t mod)
{
    point_t P = { .x = 9u, .y = 20u };
    point_t Q = { .x = 0u, .y = 1u };

    for (int i = 0; i < 32; i++) {
        point_double(&P, mod);
        if (k & (1u << i))
            point_add(&Q, &P, mod);
    }
    *R = Q;
}

void ecc_bench(void)
{
    printf("\n[BIOS] ECC benchmark starting...\n");

    const uint32_t mod         = 4294967279u;
    const uint32_t base_scalar = 0xa5a5a5a5u;
    const int iterations        = 400;

    uint32_t t_start = get_timer0_ticks();

    point_t acc = { .x = 0u, .y = 0u };
    for (int i = 0; i < iterations; i++) {
        point_t R;
        uint32_t k = base_scalar ^ (uint32_t)i;
        ecc_scalar(&R, k, mod);

        acc.x ^= R.x;
        acc.y ^= R.y;
    }

    uint32_t t_end   = get_timer0_ticks();
    uint32_t elapsed = t_start - t_end;

    printf("[BIOS] ECC benchmark complete.\n");
    printf("[BIOS] iterations : %d\n", iterations);
    printf("[BIOS] checksum   : x=0x%08x y=0x%08x\n", acc.x, acc.y);
    print_time_ticks_ms(elapsed);

}

#ifndef CONFIG_BIOS_NO_BOOT
static void boot_sequence(void)
{
#ifdef CSR_UART_BASE
	if (serialboot() == 0)
		return;
#endif
#ifdef FLASH_BOOT_ADDRESS
	flashboot();
#endif
#ifdef ROM_BOOT_ADDRESS
	romboot();
#endif
#if defined(CSR_SPISDCARD_BASE) || defined(CSR_SDCARD_CORE_BASE)
	sdcardboot();
#endif
#if defined(CSR_SATA_SECTOR2MEM_BASE)
	sataboot();
#endif
#ifdef CSR_ETHMAC_BASE
#ifdef CSR_ETHPHY_MODE_DETECTION_MODE_ADDR
	eth_mode();
#endif
	netboot(0, NULL);
#endif
	printf("No boot medium found\n");
}
#endif

__attribute__((__used__)) int main(int i, char **c)
{
#ifndef BIOS_CONSOLE_DISABLE
	char buffer[CMD_LINE_BUFFER_SIZE];
	char *params[MAX_PARAM];
	char *command;
	struct command_struct *cmd;
	int nb_params;
#endif
	int sdr_ok;

#ifdef CONFIG_CPU_HAS_INTERRUPT
	irq_setmask(0);
	irq_setie(1);
#endif
#ifdef CSR_UART_BASE
	uart_init();
#endif

#ifdef CONFIG_HAS_I2C
	i2c_send_init_cmds();
#endif

#ifndef CONFIG_BIOS_NO_PROMPT
	printf("\n");
	printf("\e[1m        __   _ __      _  __\e[0m\n");
	printf("\e[1m       / /  (_) /____ | |/_/\e[0m\n");
	printf("\e[1m      / /__/ / __/ -_)>  <\e[0m\n");
	printf("\e[1m     /____/_/\\__/\\__/_/|_|\e[0m\n");
	printf("\e[1m   Build your hardware, easily!\e[0m\n");
	printf("\n");
	printf(" (c) Copyright 2012-2024 Enjoy-Digital\n");
	printf(" (c) Copyright 2007-2015 M-Labs\n");
	printf("\n");
#ifndef CONFIG_BIOS_NO_BUILD_TIME
	printf(" BIOS built on "__DATE__" "__TIME__"\n");
#endif
#ifndef CONFIG_BIOS_NO_CRC
	crcbios();
#endif
	printf("\n");
	printf(" LiteX git sha1: "LITEX_GIT_SHA1"\n");
	printf("\n");
	printf("--=============== \e[1mSoC\e[0m ==================--\n");
	printf("\e[1mCPU\e[0m:\t\t%s @ %dMHz\n",
		CONFIG_CPU_HUMAN_NAME,
#ifdef CONFIG_CPU_CLK_FREQ
		CONFIG_CPU_CLK_FREQ/1000000);
#else
		CONFIG_CLOCK_FREQUENCY/1000000);
#endif
	printf("\e[1mBUS\e[0m:\t\t%s %d-bit @ %dGiB\n",
		CONFIG_BUS_STANDARD,
		CONFIG_BUS_DATA_WIDTH,
		(1 << (CONFIG_BUS_ADDRESS_WIDTH - 30)));
	printf("\e[1mCSR\e[0m:\t\t%d-bit data\n",
		CONFIG_CSR_DATA_WIDTH);
	printf("\e[1mROM\e[0m:\t\t");
	print_size(ROM_SIZE);
	printf("\n");
	printf("\e[1mSRAM\e[0m:\t\t");
	print_size(SRAM_SIZE);
	printf("\n");
#ifdef CONFIG_L2_SIZE
	printf("\e[1mL2\e[0m:\t\t");
	print_size(CONFIG_L2_SIZE);
	printf("\n");
#endif
#ifdef CSR_SPIFLASH_CORE_BASE
	printf("\e[1mFLASH\e[0m:\t\t");
	print_size(SPIFLASH_MODULE_TOTAL_SIZE);
	printf("\n");
#endif
#ifdef MAIN_RAM_SIZE
#ifdef CSR_SDRAM_BASE
	uint64_t supported_memory = sdram_get_supported_memory();
	printf("\e[1mSDRAM\e[0m:\t\t");
	print_size(supported_memory);
	printf(" %d-bit @ %dMT/s ",
		sdram_get_databits(),
		sdram_get_freq()/1000000);
	printf("(CL-%d",
		sdram_get_cl());
	if (sdram_get_cwl() != -1)
		printf(" CWL-%d", sdram_get_cwl());
	printf(")\n");
#endif
	printf("\e[1mMAIN-RAM\e[0m:\t");
	print_size(MAIN_RAM_SIZE);
	printf("\n");
#endif
	printf("\n");
#endif

    sdr_ok = 1;

#ifdef CSR_HYPERRAM_BASE
    hyperram_init();
#endif

#if defined(CSR_ETHMAC_BASE) || defined(MAIN_RAM_BASE) || defined(CSR_SPIFLASH_CORE_BASE)
    printf("--========== \e[1mInitialization\e[0m ============--\n");
#ifdef CSR_ETHMAC_BASE
	eth_init();
#endif

	/* Initialize and test SPIRAM */
#ifdef CSR_SPIRAM_CORE_BASE
	spiram_init();
#endif
	printf("\n");

	/* Initialize and test DRAM */
#ifdef CSR_SDRAM_BASE
	sdr_ok = sdram_init();
#else
	/* Test Main RAM when present and not pre-initialized */
#ifdef MAIN_RAM_BASE
#ifndef CONFIG_MAIN_RAM_INIT
	sdr_ok = memtest((unsigned int *) MAIN_RAM_BASE, min(MAIN_RAM_SIZE, MEMTEST_DATA_SIZE));
	memspeed((unsigned int *) MAIN_RAM_BASE, min(MAIN_RAM_SIZE, MEMTEST_DATA_SIZE), false, 0);
#endif
#endif
#endif
	if (sdr_ok != 1)
		printf("Memory initialization failed\n");
#endif

	/* Initialize and test SPIFLASH */
#ifdef CSR_SPIFLASH_CORE_BASE
	spiflash_init();
#endif
	printf("\n");


	/* Initialize Video Framebuffer FIXME: Move */
#ifdef CSR_VIDEO_FRAMEBUFFER_BASE
	video_framebuffer_vtg_enable_write(0);
	video_framebuffer_dma_enable_write(0);
	video_framebuffer_vtg_enable_write(1);
	video_framebuffer_dma_enable_write(1);
#endif

	/* Execute  initialization functions */
	init_dispatcher();

	/* Execute Boot sequence */
#ifndef CONFIG_BIOS_NO_BOOT
	if(sdr_ok) {
		printf("--============== \e[1mBoot\e[0m ==================--\n");
		boot_sequence();
		printf("\n");
	}
#endif

	/* Console */
#ifdef BIOS_CONSOLE_DISABLE
	printf("--======= \e[1mDone (No Console) \e[0m ==========--\n");
#else
	printf("--============= \e[1mConsole\e[0m ================--\n");
#if !defined(BIOS_CONSOLE_LITE) && !defined(BIOS_CONSOLE_NO_HISTORY)
	hist_init();
#endif

printf("\n%s", PROMPT);
while(1) {
    readline(buffer, CMD_LINE_BUFFER_SIZE);
    if (buffer[0] != 0) {
        printf("\n");
        nb_params = get_param(buffer, &command, params);
        cmd = command_dispatcher(command, nb_params, params);

        if (!cmd) {
            if (!strcmp(command, "rsa")) {
                rsa_bench();
            } else if (!strcmp(command, "ecc")) {
                ecc_bench();
            } else {
                printf("Command not found");
            }
        }
    }
    printf("\n%s", PROMPT);
}

#endif
	return 0;
}
