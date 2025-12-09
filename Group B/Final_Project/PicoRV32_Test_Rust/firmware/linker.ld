/* linker.ld */
ENTRY(_start)

MEMORY {
  RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 64K
}

SECTIONS
{
  /* start of image */
  . = ORIGIN(RAM);

  /* keep only code in .text; no rodata here */
  .text : {
    *(.init)            /* crt0.S _start */
    *(.text*)           /* code */
  } > RAM

  /* ensure rodata is aligned for 32/64-bit loads */
  . = ALIGN(8);
  .rodata : {
    *(.rodata*)
  } > RAM

  /* initialized data */
  .data : {
    *(.data*)
  } > RAM

  /* zero-initialized */
  .bss (NOLOAD) : {
    __bss_start = .;
    *(.bss*) *(COMMON)
    __bss_end   = .;
  } > RAM

  /* heap/stack symbols */
  . = ALIGN(4);
  _heap_start = .;
  _heap_end   = ORIGIN(RAM) + LENGTH(RAM);
  _stack_top  = ORIGIN(RAM) + LENGTH(RAM);

  PROVIDE(_end = _heap_start);
}
