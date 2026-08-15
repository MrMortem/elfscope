# elfscope

`elfscope` is an interactive terminal inspector for 64-bit, little-endian ELF
files. The application is written entirely in x86-64 NASM assembly and talks
directly to Linux through system calls; it does not use libc or a terminal UI
library.

## Build and run

Requirements are NASM, GNU `ld`, GNU Make, and a Linux x86-64 host.

```sh
make
./elfscope /bin/ls
```

The inspector validates every ELF table before reading it and provides three
views:

- ELF header metadata
- program headers (segments)
- section headers, including names from the section-name string table

Use `1`, `2`, and `3` to switch views; `Tab`, `h`, and `l` also move between
views. Navigate table rows with the arrow keys or `j`/`k`, jump with `g`/`G`,
page with Page Up/Page Down, and exit with `q`, Escape, or Ctrl-C.

The terminal is put into raw mode while the program runs and restored on every
normal exit. Run `make test` for parser and pseudo-terminal smoke tests.

## Scope

The current parser supports ELFCLASS64 files using ELFDATA2LSB byte order. It
handles ordinary and extended ELF header counts (`PN_XNUM`, `SHN_XINDEX`, and
the extended section count encoding), and rejects truncated or out-of-bounds
tables before entering the UI.

