/* trap.S — print mcause/mepc/mtval (hex) then halt */
.section .trap, "ax"
.align 2
.globl _trap_vector
_trap_vector:
  csrr a0, mcause        # a0 = cause
  csrr a1, mepc          # a1 = faulting PC
  csrr a2, mtval         # a2 = extra info (e.g., bad address or instruction)
  li   t0, 0x10000000    # UART_TX MMIO base

# putch(a3): waits while busy (bit0==1), then writes byte a3
putch:
1: lw   t1, 0(t0)
   andi t1, t1, 1
   bnez t1, 1b
   sw   a3, 0(t0)
   ret

# print single hex nibble in a3
nib:
   andi a3, a3, 0xF
   li   t2, 10
   blt  a3, t2, 2f
   addi a3, a3, -10
   addi a3, a3, 'A'
   j    3f
2: addi a3, a3, '0'
3: jal  ra, putch
   ret

# print a0 as 0xXXXXXXXX
phex32:
   li   a3, '0';   jal ra, putch
   li   a3, 'x';   jal ra, putch
   li   t3, 28
4: srl  a3, a0, t3
   jal  ra, nib
   addi t3, t3, -4
   bgez t3, 4b
   ret

# print label + value
plab32:           # a0=value, a4 points to label string
5: lbu  a3, 0(a4)
   beqz a3, 6f
   jal  ra, putch
   addi a4, a4, 1
   j    5b
6: jal  ra, phex32
   li   a3, 13;    jal ra, putch
   li   a3, 10;    jal ra, putch
   ret

# entry: print three lines, then spin
trap_entry:
   la   a4, lab1;  mv a0, a0;        jal ra, plab32  # mcause
   la   a4, lab2;  mv a0, a1;        jal ra, plab32  # mepc
   la   a4, lab3;  mv a0, a2;        jal ra, plab32  # mtval
halt: j halt

.section .rodata
lab1: .asciz "mcause="
lab2: .asciz "mepc="
lab3: .asciz "mtval="
