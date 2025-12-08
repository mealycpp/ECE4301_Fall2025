#include "xparameters.h"
#include "xil_io.h"
#include "xgpio.h"
#include "xil_printf.h"
#include <stdint.h>

// ============================================================================
// AXI-Lite Poseidon Accelerator Register Map
// ============================================================================
#define POSEIDON_BASE      XPAR_POSEIDON_ACCEL_AXI_L_0_BASEADDR
#define REG_CONTROL        0x00     // [0]=start, [1]=done (RO)
#define REG_INPUT0         0x10
#define REG_INPUT1         0x14
#define REG_INPUT2         0x18
#define REG_OUTPUT0        0x30
#define REG_OUTPUT1        0x34
#define REG_OUTPUT2        0x38

// ============================================================================
// GPIO
// LEDs  → AXI GPIO0 (DeviceId=0, channel 1)
// Switches → AXI GPIO1 via direct AXI access
// ============================================================================
#define GPIO_LED_DEV_ID    0
#define LED_CHANNEL        1

#define SWITCHES_BASEADDR  XPAR_SWITCHES_BASEADDR
#define AXI_GPIO_DATA      0x0
#define AXI_GPIO_TRI       0x4

#define SW_ONOFF_BIT       0
#define SW_RESET_BIT       1

// ============================================================================
// TIMER (Global Timer, no driver required)
// ============================================================================
#define GT_BASEADDR   XPAR_PS7_GLOBALTIMER_0_BASEADDR
#define CPU_CLK_HZ    XPAR_CPU_CORE_CLOCK_FREQ_HZ   // 650 MHz on your Pynq-Z2

static void init_global_timer(void)
{
    uint32_t ctrl = Xil_In32(GT_BASEADDR + 0x08);
    ctrl |= 0x01; // enable
    Xil_Out32(GT_BASEADDR + 0x08, ctrl);
}

static uint64_t gt_read(void)
{
    uint32_t hi1, lo, hi2;
    do {
        hi1 = Xil_In32(GT_BASEADDR + 0x04);
        lo  = Xil_In32(GT_BASEADDR + 0x00);
        hi2 = Xil_In32(GT_BASEADDR + 0x04);
    } while (hi1 != hi2);

    return ((uint64_t)hi1 << 32) | lo;
}

// ============================================================================
// SOFTWARE Poseidon (matches poseidon_core.v)
// ============================================================================

static inline uint32_t sbox(uint32_t x)
{
    uint32_t x2 = x * x;
    uint32_t x4 = x2 * x2;
    return x4 * x;
}

static const uint32_t RC0[8] = {
    0x243F6A88u,
    0x85A308D3u,
    0x13198A2Eu,
    0x03707344u,
    0xA4093822u,
    0x299F31D0u,
    0x082EFA98u,
    0xEC4E6C89u
};

static const uint32_t RC1[8] = {
    0x452821E6u,
    0x38D01377u,
    0xBE5466CFu,
    0x34E90C6Cu,
    0xC0AC29B7u,
    0xC97C50DDu,
    0x3F84D5B5u,
    0xB5470917u
};

static const uint32_t RC2[8] = {
    0x9216D5D9u,
    0x8979FB1Bu,
    0xD1310BA6u,
    0x98DFB5ACu,
    0x2FFD72DBu,
    0xD01ADFB7u,
    0xB8E1AFEDu,
    0x6A267E96u
};

static void poseidon_sw_hash(uint32_t in[3], uint32_t out[3])
{
    uint32_t st0 = in[0];
    uint32_t st1 = in[1];
    uint32_t st2 = in[2];

    for (int r = 0; r < 8; r++) {
        uint32_t a0 = st0 + RC0[r];
        uint32_t a1 = st1 + RC1[r];
        uint32_t a2 = st2 + RC2[r];

        uint32_t s0, s1, s2;

        // full rounds: r = 0,1,6,7
        if (r < 2 || r >= 6) {
            s0 = sbox(a0);
            s1 = sbox(a1);
            s2 = sbox(a2);
        } else {
            // partial rounds: r = 2,3,4,5
            s0 = sbox(a0);
            s1 = a1;
            s2 = a2;
        }

        // MDS: [2 1 1; 1 2 1; 1 1 2]
        uint32_t m0 = (s0 << 1) + s1       + s2;
        uint32_t m1 = s0       + (s1 << 1) + s2;
        uint32_t m2 = s0       + s1       + (s2 << 1);

        st0 = m0;
        st1 = m1;
        st2 = m2;
    }

    out[0] = st0;
    out[1] = st1;
    out[2] = st2;
}

// ============================================================================
// HARDWARE Poseidon accelerator (AXI-Lite)
// ============================================================================

// Debug version: single hash + register readbacks
static void poseidon_hw_hash_debug(uint32_t in[3], uint32_t out[3])
{
    
    xil_printf("=== HW DEBUG CALL ===\r\n");
    xil_printf("POSEIDON_BASE = 0x%08x\r\n", (unsigned)POSEIDON_BASE);

    // write inputs
    Xil_Out32(POSEIDON_BASE + REG_INPUT0, in[0]);
    Xil_Out32(POSEIDON_BASE + REG_INPUT1, in[1]);
    Xil_Out32(POSEIDON_BASE + REG_INPUT2, in[2]);

    // read back input registers
    uint32_t rin0 = Xil_In32(POSEIDON_BASE + REG_INPUT0);
    uint32_t rin1 = Xil_In32(POSEIDON_BASE + REG_INPUT1);
    uint32_t rin2 = Xil_In32(POSEIDON_BASE + REG_INPUT2);
    xil_printf("DBG INREGS: %08x %08x %08x\r\n", rin0, rin1, rin2);

    // write start bit = 1
    Xil_Out32(POSEIDON_BASE + REG_CONTROL, 0x1u);

    // poll done-bit (bit1)
    uint32_t ctrl;
    do {
        ctrl = Xil_In32(POSEIDON_BASE + REG_CONTROL);
    } while (((ctrl >> 1) & 0x1u) == 0u);

    // read outputs
    out[0] = Xil_In32(POSEIDON_BASE + REG_OUTPUT0);
    out[1] = Xil_In32(POSEIDON_BASE + REG_OUTPUT1);
    out[2] = Xil_In32(POSEIDON_BASE + REG_OUTPUT2);

    xil_printf("DBG CTRL after: 0x%08x\r\n", ctrl);
    xil_printf("DBG HW OUT   : %08x %08x %08x\r\n", out[0], out[1], out[2]);
    xil_printf("======================\r\n");
}

// Fast version for benchmarking (no debug prints inside loop)
static void poseidon_hw_hash_fast(uint32_t in[3], uint32_t out[3])
{
    Xil_Out32(POSEIDON_BASE + REG_INPUT0, in[0]);
    Xil_Out32(POSEIDON_BASE + REG_INPUT1, in[1]);
    Xil_Out32(POSEIDON_BASE + REG_INPUT2, in[2]);

    Xil_Out32(POSEIDON_BASE + REG_CONTROL, 0x1u);

    while (((Xil_In32(POSEIDON_BASE + REG_CONTROL) >> 1) & 0x1u) == 0u)
        ;

    out[0] = Xil_In32(POSEIDON_BASE + REG_OUTPUT0);
    out[1] = Xil_In32(POSEIDON_BASE + REG_OUTPUT1);
    out[2] = Xil_In32(POSEIDON_BASE + REG_OUTPUT2);
}

// ============================================================================
// Benchmark helpers with ~1 Hz LED "activity" blink
// ============================================================================
#define NUM_HASHES 10000u

// Toggle LED every ~1 second using global timer, without blocking.
static void maybe_blink_led(XGpio *GpioLed, uint32_t *led_mask,
                            uint64_t *next_blink_tick)
{
    uint64_t now = gt_read();
    if (now >= *next_blink_tick) {
        // toggle LED bit0
        if (*led_mask == 0)
            *led_mask = 0x1;
        else
            *led_mask = 0x0;

        XGpio_DiscreteWrite(GpioLed, LED_CHANNEL, *led_mask);

        // schedule next blink in ~1 second
        *next_blink_tick = now + (uint64_t)CPU_CLK_HZ;
    }
}

static void run_benchmarks(XGpio *GpioLed)
{
    uint32_t in[3]  = { 0x12345678u, 0xAABBCCDDu, 0xCAFEBABEu };
    uint32_t out_sw[3], out_hw[3];

    xil_printf("=== Poseidon Benchmark Start ===\r\n");
    xil_printf("Input: %08x %08x %08x\r\n", in[0], in[1], in[2]);
    xil_printf("NUM_HASHES = %u\r\n", (unsigned)NUM_HASHES);

    // One debug HW call to inspect registers and outputs
    uint32_t debug_hw[3];
    poseidon_hw_hash_debug(in, debug_hw);

    // LED blink state
    uint32_t led_mask = 0x0;
    XGpio_DiscreteWrite(GpioLed, LED_CHANNEL, led_mask);
    uint64_t next_blink = gt_read() + (uint64_t)CPU_CLK_HZ;

    // --------------------------------------------------------
    // Software benchmark
    // --------------------------------------------------------
    uint64_t t0 = gt_read();
    for (uint32_t i = 0; i < NUM_HASHES; i++) {
        poseidon_sw_hash(in, out_sw);
        maybe_blink_led(GpioLed, &led_mask, &next_blink);
    }
    uint64_t t1 = gt_read();
    uint32_t sw_cycles = (uint32_t)(t1 - t0);

    // --------------------------------------------------------
    // Hardware benchmark (fast, no debug prints in loop)
    // --------------------------------------------------------
    t0 = gt_read();
    for (uint32_t i = 0; i < NUM_HASHES; i++) {
        poseidon_hw_hash_fast(in, out_hw);
        maybe_blink_led(GpioLed, &led_mask, &next_blink);
    }
    t1 = gt_read();
    uint32_t hw_cycles = (uint32_t)(t1 - t0);

    // turn LED off after processing
    XGpio_DiscreteWrite(GpioLed, LED_CHANNEL, 0x0);

    // --------------------------------------------------------
    // Metrics: cycles, time (µs), throughput, speedup
    // --------------------------------------------------------
    // time_us = cycles * 1e6 / CPU_CLK_HZ
    uint32_t sw_time_us = (uint32_t)(((uint64_t)sw_cycles * 1000000ULL) /
                                     (uint64_t)CPU_CLK_HZ);
    uint32_t hw_time_us = (uint32_t)(((uint64_t)hw_cycles * 1000000ULL) /
                                     (uint64_t)CPU_CLK_HZ);

    // throughput = NUM_HASHES * CPU_CLK_HZ / cycles (hashes/s)
    uint32_t sw_throughput = (uint32_t)(((uint64_t)NUM_HASHES * (uint64_t)CPU_CLK_HZ) /
                                        (uint64_t)sw_cycles);
    uint32_t hw_throughput = (uint32_t)(((uint64_t)NUM_HASHES * (uint64_t)CPU_CLK_HZ) /
                                        (uint64_t)hw_cycles);

    // speedup ≈ SW/HW as Q8.8 fixed point
    uint32_t speedup_q8 = (uint32_t)(((uint64_t)sw_cycles << 8) / (uint64_t)hw_cycles);
    uint32_t speedup_int  = speedup_q8 >> 8;
    uint32_t speedup_frac = (speedup_q8 & 0xFFu) * 100u / 256u;

    xil_printf("SW out: %08x %08x %08x\r\n", out_sw[0], out_sw[1], out_sw[2]);
    xil_printf("HW out: %08x %08x %08x\r\n", out_hw[0], out_hw[1], out_hw[2]);

    xil_printf("SW: cycles=%u, time=%u us, throughput=%u hashes/s\r\n",
               sw_cycles, sw_time_us, sw_throughput);
    xil_printf("HW: cycles=%u, time=%u us, throughput=%u hashes/s\r\n",
               hw_cycles, hw_time_us, hw_throughput);

    xil_printf("Speedup ≈ %u.%02u x\r\n", speedup_int, speedup_frac);
    xil_printf("=== Benchmark complete ===\r\n");
}

// ============================================================================
// MAIN APPLICATION
// ============================================================================
int main()
{
    xil_printf("System booting...\r\n");

    XGpio GpioLed;
    int status = XGpio_Initialize(&GpioLed, GPIO_LED_DEV_ID);
    if (status != XST_SUCCESS) {
        xil_printf("LED GPIO init failed\r\n");
        return -1;
    }

    XGpio_SetDataDirection(&GpioLed, LED_CHANNEL, 0x0); // LED as output
    XGpio_DiscreteWrite(&GpioLed, LED_CHANNEL, 0x0);

    // switches as input
    Xil_Out32(SWITCHES_BASEADDR + AXI_GPIO_TRI, 0xFFFFFFFF);

    init_global_timer();

    xil_printf("READY. Flip ON/OFF switch to start benchmark.\r\n");

    uint32_t sw_prev_reset = 1;
    int system_enabled = 0;

    while (1)
    {
        uint32_t sw = Xil_In32(SWITCHES_BASEADDR + AXI_GPIO_DATA);
        uint32_t sw_onoff = (sw >> SW_ONOFF_BIT) & 1u;
        uint32_t sw_reset = (sw >> SW_RESET_BIT) & 1u;

        // reset on negative edge
        if (sw_prev_reset == 1u && sw_reset == 0u) {
            xil_printf("RESET triggered.\r\n");
            XGpio_DiscreteWrite(&GpioLed, LED_CHANNEL, 0x0);
            system_enabled = 0;
        }
        sw_prev_reset = sw_reset;

        if (sw_onoff && !system_enabled) {
            system_enabled = 1;
            run_benchmarks(&GpioLed);
            xil_printf("Turn OFF ON/OFF switch or toggle RESET to rerun.\r\n");
        }

        if (!sw_onoff)
            system_enabled = 0;
    }

    return 0;
}
