@echo off
setlocal ENABLEDELAYEDEXPANSION

rem -------- tools --------
set CC=riscv-none-elf-gcc
set OBJCOPY=riscv-none-elf-objcopy
set PY=python

rem -------- ISA / ABI --------
rem You said all targets will be RV32IMC cores (with CSRs).
rem If your toolchain is older and doesn't recognize _zicsr, change to rv32imc.
if "%ARCH%"=="" set ARCH=rv32imc_zicsr
if "%ABI%"==""  set ABI=ilp32

rem -------- common flags --------
set COMMON_CFLAGS=-std=c99 -O3 -march=%ARCH% -mabi=%ABI% -mcmodel=medany -mstrict-align -ffreestanding -fno-builtin
set SECFLAGS=-ffunction-sections -fdata-sections
set LDFLAGS=-nostdlib -nostartfiles -Wl,--gc-sections -Wl,-Map=prog.map -T linker.ld
set SPECS=-specs=nosys.specs
set LIBGROUP=-Wl,--start-group -lc -lgcc -Wl,--end-group

rem If you ever see odd jumps due to relaxation, uncomment next line:
rem set LDFLAGS=%LDFLAGS% -Wl,--no-relax

echo [1/3] Compile+link -> prog.elf
"%CC%" %COMMON_CFLAGS% %SECFLAGS% ^
  crt0.S trap.S main.c ^
  %LDFLAGS% %SPECS% %LIBGROUP% -o prog.elf || goto :err

echo [2/3] ELF -> raw binary
"%OBJCOPY%" -O binary prog.elf prog.bin || goto :err

echo [3/3] BIN -> Vivado-friendly HEX
"%PY%" make_hex.py || goto :err

echo.
echo SUCCESS: created prog.hex
exit /b 0

:err
echo.
echo BUILD FAILED
exit /b 1
