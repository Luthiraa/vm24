ENTRY(_start)
PHDRS {
    text PT_LOAD FILEHDR PHDRS FLAGS(5);
    data PT_LOAD FLAGS(6);
    stack PT_GNU_STACK FLAGS(6);
}
SECTIONS {
    . = SIZEOF_HEADERS;
    .text : {
        *(.text*)
        *(.rodata*)
    } :text
    . = ALIGN(4096);
    .data : {
        *(.data*)
    } :data
    .bss (NOLOAD) : {
        *(.bss*)
        *(COMMON)
    } :data
    /DISCARD/ : {
        *(.comment*)
        *(.eh_frame*)
        *(.note*)
        *(.gnu*)
        *(.dynamic)
        *(.dynsym)
        *(.dynstr)
        *(.hash)
    }
}
