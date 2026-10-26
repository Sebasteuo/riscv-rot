
OUTPUT_ARCH(riscv)
ENTRY(_start)
SECTIONS
{
  . = 0x80000000;
  .text : { *(.text.entry) *(.text*) }
  .rodata : { *(.rodata*) }
  .data : {
    __cfg = .;
    *(.data.cfg)
    *(.data*)
  }
  . = ALIGN(8);
  __bss_start = .;
  .bss : { *(.bss*) *(COMMON) }
  . = ALIGN(8);
  __bss_end = .;
}
