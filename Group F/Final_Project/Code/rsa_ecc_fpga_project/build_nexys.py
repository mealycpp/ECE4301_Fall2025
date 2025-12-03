#!/usr/bin/env python3

from litex_boards.targets import digilent_nexys4ddr
from litex.soc.integration.builder import *

# Get the standard SoC
soc = digilent_nexys4ddr.BaseSoC(
    sys_clk_freq        = int(75e6),
    cpu_type            = "vexriscv",
    integrated_rom_size = 0x8000,  # 32 KB boot ROM at 0x00000000
)

# Build with explicit CSR configuration
builder = Builder(
    soc,
    output_dir        = "build",
    csr_csv           = "build/csr.csv",
    compile_software  = True,
)

builder.build()
