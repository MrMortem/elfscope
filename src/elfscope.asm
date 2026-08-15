; elfscope - interactive ELF64 inspector
; Linux x86-64, NASM syntax, no libc

bits 64
default rel

%define SYS_read        0
%define SYS_write       1
%define SYS_close       3
%define SYS_fstat       5
%define SYS_mmap        9
%define SYS_munmap      11
%define SYS_ioctl       16
%define SYS_exit        60
%define SYS_openat      257

%define AT_FDCWD        -100
%define PROT_READ       1
%define MAP_PRIVATE     2

%define TCGETS          0x5401
%define TCSETS          0x5402
%define TIOCGWINSZ      0x5413

%define ELF_HDR_SIZE    64
%define ELF_PHDR_SIZE   56
%define ELF_SHDR_SIZE   64
%define PN_XNUM         0xffff
%define SHN_XINDEX      0xffff

%define OUTBUF_SIZE     65536
%define MAX_ROWS        200
%define WIDE_COLS       102

section .rodata

usage:          db "Usage: elfscope <elf-file>",10
                db "Inspect a 64-bit little-endian ELF file in an interactive terminal.",10
                db "Keys: 1/2/3 views, arrows or j/k navigate, Tab cycles, q quits.",10,0
version_text:   db "elfscope 0.1.0",10,0
arg_help:       db "--help",0
arg_help_s:     db "-h",0
arg_version:    db "--version",0

err_prefix:     db "elfscope: ",0
err_open:       db "cannot open input file",0
err_stat:       db "cannot read input file metadata",0
err_empty:      db "input is too small to contain an ELF64 header",0
err_map:        db "cannot map input file",0
err_magic:      db "input does not have ELF magic",0
err_class:      db "only 64-bit ELF files are supported",0
err_encoding:   db "only little-endian ELF files are supported",0
err_version:    db "unsupported ELF identification version",0
err_ehsize:     db "invalid ELF header size",0
err_phdr:       db "program header table is truncated or invalid",0
err_shdr:       db "section header table is truncated or invalid",0
err_shstr:      db "section-name string table is truncated or invalid",0
err_tty:        db "standard input is not an interactive terminal",0
err_termios:    db "cannot enable terminal raw mode",0

ansi_enter:     db 27,"[?1049h",27,"[?25l",27,"[2J",0
ansi_leave:     db 27,"[0m",27,"[?25h",27,"[?1049l",0
ansi_home:      db 27,"[H",27,"[2J",0
ansi_reset:     db 27,"[0m",0
ansi_boldcyan:  db 27,"[1;36m",0
ansi_dim:       db 27,"[2m",0
ansi_tab:       db 27,"[30;46m",0
ansi_select:    db 27,"[30;47m",0

title:          db " ELFSCOPE ",0
file_label:     db "  File: ",0
tab_header:     db " 1 Header ",0
tab_program:    db " 2 Program Headers ",0
tab_sections:   db " 3 Sections ",0
nav_hint:       db "  Tab/h/l: views   arrows/j/k: navigate   g/G: first/last   q: quit",0
line_rule:      db "-------------------------------------------------------------------------------",0

hdr_title:      db "ELF Header",10,10,0
lbl_class:      db "  Class:                 ",0
lbl_data:       db "  Data:                  ",0
lbl_identver:   db "  Ident version:         ",0
lbl_osabi:      db "  OS/ABI:                ",0
lbl_abiver:     db "  ABI version:           ",0
lbl_type:       db "  Object type:           ",0
lbl_machine:    db "  Machine:               ",0
lbl_entry:      db "  Entry point:           ",0
lbl_phoff:      db "  Program header offset: ",0
lbl_phnum:      db "  Program header count:  ",0
lbl_phentsize:  db "  Program header size:   ",0
lbl_shoff:      db "  Section header offset: ",0
lbl_shnum:      db "  Section header count:  ",0
lbl_shentsize:  db "  Section header size:   ",0
lbl_shstrndx:   db "  Section name table:    ",0
lbl_flags:      db "  Architecture flags:    ",0
lbl_filesize:   db "  File size:             ",0
str_elf64:      db "ELF64",0
str_little:     db "little-endian",0

program_title:  db "Program Headers",0
program_cols:   db "  #    Type         Flags  Offset              Virtual address     File size           Memory size",10,0
program_cols_narrow: db "  #    Type       Flg  Offset              File size           Memory size",10,0
section_title:  db "Section Headers",0
section_cols:   db "  #    Name                 Type         Address             Offset              Size",10,0
section_cols_narrow: db "  #    Name              Type       Offset              Size",10,0
empty_table:    db "  (none)",10,0
selected_lbl:   db "Selected ",0
of_lbl:         db " of ",0
detail_paddr:   db "  physical=",0
detail_vaddr:   db "  virtual=",0
detail_address: db "  address=",0
detail_align:   db "  align=",0
detail_flags:   db "  flags=",0
detail_link:    db "  link=",0
detail_info:    db "  info=",0
detail_entsize: db "  entry-size=",0

unknown:        db "UNKNOWN",0
type_none:      db "NONE",0
type_rel:       db "REL",0
type_exec:      db "EXEC",0
type_dyn:       db "DYN",0
type_core:      db "CORE",0
machine_none:   db "No machine",0
machine_x86:    db "Intel 80386",0
machine_x64:    db "AMD x86-64",0
machine_arm:    db "ARM",0
machine_aarch64: db "AArch64",0
machine_riscv:  db "RISC-V",0

osabi_sysv:     db "UNIX System V",0
osabi_hpux:     db "HP-UX",0
osabi_netbsd:   db "NetBSD",0
osabi_linux:    db "GNU/Linux",0
osabi_solaris:  db "Solaris",0
osabi_aix:      db "AIX",0
osabi_freebsd:  db "FreeBSD",0
osabi_openbsd:  db "OpenBSD",0

pt_null:        db "NULL",0
pt_load:        db "LOAD",0
pt_dynamic:     db "DYNAMIC",0
pt_interp:      db "INTERP",0
pt_note:        db "NOTE",0
pt_shlib:       db "SHLIB",0
pt_phdr:        db "PHDR",0
pt_tls:         db "TLS",0
pt_ehframe:     db "GNU_EH_FRAME",0
pt_stack:       db "GNU_STACK",0
pt_relro:       db "GNU_RELRO",0
pt_property:    db "GNU_PROPERTY",0

sht_null:       db "NULL",0
sht_progbits:   db "PROGBITS",0
sht_symtab:     db "SYMTAB",0
sht_strtab:     db "STRTAB",0
sht_rela:       db "RELA",0
sht_hash:       db "HASH",0
sht_dynamic:    db "DYNAMIC",0
sht_note:       db "NOTE",0
sht_nobits:     db "NOBITS",0
sht_rel:        db "REL",0
sht_shlib:      db "SHLIB",0
sht_dynsym:     db "DYNSYM",0
sht_init_array: db "INIT_ARRAY",0
sht_fini_array: db "FINI_ARRAY",0
sht_preinit:    db "PREINIT_ARRAY",0
sht_group:      db "GROUP",0
sht_symtab_shndx: db "SYMTAB_SHNDX",0

hex_digits:     db "0123456789abcdef"
newline:        db 10,0
space:          db " ",0
placeholder:    db "<no-name>",0

section .bss

input_fd:       resq 1
file_base:      resq 1
file_size:      resq 1
file_path:      resq 1
ph_count:       resq 1
sh_count:       resq 1
shstr_index:    resq 1
shstr_base:     resq 1
shstr_size:     resq 1

current_view:   resb 1
tty_active:     resb 1
wide_layout:    resb 1
                alignb 8
selected_row:   resq 1
scroll_row:     resq 1
term_rows:      resq 1
term_cols:      resq 1

orig_termios:   resb 36
raw_termios:    resb 36
winsize:        resb 8
statbuf:        resb 144
keybuf:         resb 16

out_pos:        resq 1
outbuf:         resb OUTBUF_SIZE

section .text
global _start

_start:
    mov rax, [rsp]
    cmp rax, 2
    jne .usage

    mov rdi, [rsp + 16]
    lea rsi, [arg_help]
    call streq
    test eax, eax
    jz .help
    mov rdi, [rsp + 16]
    lea rsi, [arg_help_s]
    call streq
    test eax, eax
    jz .help
    mov rdi, [rsp + 16]
    lea rsi, [arg_version]
    call streq
    test eax, eax
    jz .version

    mov rax, [rsp + 16]
    mov [file_path], rax
    mov rdi, rax
    call load_and_validate
    call terminal_enter

.event_loop:
    call render_screen
    xor eax, eax
    xor edi, edi
    lea rsi, [keybuf]
    mov edx, 16
    syscall
    test rax, rax
    jle .quit
    mov rdx, rax
    lea rsi, [keybuf]
    call handle_keys
    test eax, eax
    jnz .quit
    jmp .event_loop

.quit:
    call terminal_leave
    mov rdi, [file_base]
    mov rsi, [file_size]
    mov eax, SYS_munmap
    syscall
    mov rdi, [input_fd]
    mov eax, SYS_close
    syscall
    xor edi, edi
    mov eax, SYS_exit
    syscall

.usage:
    lea rsi, [usage]
    mov edi, 2
    call write_cstr
    mov edi, 2
    mov eax, SYS_exit
    syscall

.help:
    lea rsi, [usage]
    mov edi, 1
    call write_cstr
    xor edi, edi
    mov eax, SYS_exit
    syscall

.version:
    lea rsi, [version_text]
    mov edi, 1
    call write_cstr
    xor edi, edi
    mov eax, SYS_exit
    syscall

; rdi = path. On success, stores a validated read-only mapping and normalized
; program/section counts (including ELF extended-count encodings).
load_and_validate:
    mov rsi, rdi
    mov edi, AT_FDCWD
    xor edx, edx
    xor r10d, r10d
    mov eax, SYS_openat
    syscall
    test rax, rax
    js .open_error
    mov [input_fd], rax

    mov rdi, rax
    lea rsi, [statbuf]
    mov eax, SYS_fstat
    syscall
    test rax, rax
    js .stat_error
    mov rax, [statbuf + 48]
    cmp rax, ELF_HDR_SIZE
    jb .empty_error
    mov [file_size], rax

    xor edi, edi
    mov rsi, rax
    mov edx, PROT_READ
    mov r10d, MAP_PRIVATE
    mov r8, [input_fd]
    xor r9d, r9d
    mov eax, SYS_mmap
    syscall
    test rax, rax
    js .map_error
    mov [file_base], rax
    mov rbx, rax

    cmp dword [rbx], 0x464c457f
    jne .magic_error
    cmp byte [rbx + 4], 2
    jne .class_error
    cmp byte [rbx + 5], 1
    jne .encoding_error
    cmp byte [rbx + 6], 1
    jne .version_error
    cmp word [rbx + 52], ELF_HDR_SIZE
    jb .ehsize_error

    ; Normalize and bounds-check the section table first. Extended program
    ; counts depend on section header zero.
    movzx r12d, word [rbx + 60]       ; raw e_shnum
    mov r13, [rbx + 40]               ; e_shoff
    movzx r14d, word [rbx + 58]       ; e_shentsize
    test r13, r13
    jz .no_section_table
    cmp r14, ELF_SHDR_SIZE
    jb .shdr_error
    cmp r13, [file_size]
    ja .shdr_error
    mov rax, r13
    add rax, r14
    jc .shdr_error
    cmp rax, [file_size]
    ja .shdr_error

    test r12, r12
    jnz .section_count_ready
    mov rax, [rbx + r13 + 32]         ; shdr[0].sh_size
    mov r12, rax
.section_count_ready:
    test r12, r12
    jz .shdr_error
    mov rax, r12
    mul r14
    test rdx, rdx
    jnz .shdr_error
    add rax, r13
    jc .shdr_error
    cmp rax, [file_size]
    ja .shdr_error
    mov [sh_count], r12

    movzx eax, word [rbx + 62]
    cmp eax, SHN_XINDEX
    jne .section_index_ready
    mov eax, dword [rbx + r13 + 40]   ; shdr[0].sh_link
.section_index_ready:
    mov [shstr_index], rax
    test rax, rax                     ; SHN_UNDEF: unnamed sections
    jz .no_shstr
    cmp rax, r12
    jae .shstr_error
    imul rax, r14
    add rax, r13
    add rax, rbx
    mov r8, [rax + 24]                ; string table file offset
    mov r9, [rax + 32]                ; string table size
    cmp r8, [file_size]
    ja .shstr_error
    mov rax, r8
    add rax, r9
    jc .shstr_error
    cmp rax, [file_size]
    ja .shstr_error
    add r8, rbx
    mov [shstr_base], r8
    mov [shstr_size], r9
    jmp .sections_done

.no_shstr:
    mov qword [shstr_base], 0
    mov qword [shstr_size], 0
.sections_done:
    jmp .check_programs

.no_section_table:
    test r12, r12
    jnz .shdr_error
    mov qword [sh_count], 0
    mov qword [shstr_index], 0
    mov qword [shstr_base], 0
    mov qword [shstr_size], 0

.check_programs:
    movzx r12d, word [rbx + 56]
    cmp r12d, PN_XNUM
    jne .program_count_ready
    cmp qword [sh_count], 0
    je .phdr_error
    mov r13, [rbx + 40]
    mov r12d, dword [rbx + r13 + 44]  ; shdr[0].sh_info
.program_count_ready:
    mov [ph_count], r12
    test r12, r12
    jz .validation_done
    mov r13, [rbx + 32]
    movzx r14d, word [rbx + 54]
    test r13, r13
    jz .phdr_error
    cmp r14, ELF_PHDR_SIZE
    jb .phdr_error
    cmp r13, [file_size]
    ja .phdr_error
    mov rax, r12
    mul r14
    test rdx, rdx
    jnz .phdr_error
    add rax, r13
    jc .phdr_error
    cmp rax, [file_size]
    ja .phdr_error

.validation_done:
    ret

.open_error:     lea rsi, [err_open]
                 jmp fatal
.stat_error:     lea rsi, [err_stat]
                 jmp fatal
.empty_error:    lea rsi, [err_empty]
                 jmp fatal
.map_error:      lea rsi, [err_map]
                 jmp fatal
.magic_error:    lea rsi, [err_magic]
                 jmp fatal
.class_error:    lea rsi, [err_class]
                 jmp fatal
.encoding_error: lea rsi, [err_encoding]
                 jmp fatal
.version_error:  lea rsi, [err_version]
                 jmp fatal
.ehsize_error:   lea rsi, [err_ehsize]
                 jmp fatal
.phdr_error:     lea rsi, [err_phdr]
                 jmp fatal
.shdr_error:     lea rsi, [err_shdr]
                 jmp fatal
.shstr_error:    lea rsi, [err_shstr]
                 jmp fatal

terminal_enter:
    xor edi, edi
    mov esi, TCGETS
    lea rdx, [orig_termios]
    mov eax, SYS_ioctl
    syscall
    test rax, rax
    js .not_tty

    lea rsi, [orig_termios]
    lea rdi, [raw_termios]
    mov ecx, 36
    rep movsb
    and dword [raw_termios], ~0x500   ; ICRNL | IXON
    and dword [raw_termios + 12], ~0x800b ; ISIG | ICANON | ECHO | IEXTEN
    mov byte [raw_termios + 22], 0    ; VTIME
    mov byte [raw_termios + 23], 1    ; VMIN

    xor edi, edi
    mov esi, TCSETS
    lea rdx, [raw_termios]
    mov eax, SYS_ioctl
    syscall
    test rax, rax
    js .termios_error
    mov byte [tty_active], 1
    lea rsi, [ansi_enter]
    mov edi, 1
    call write_cstr
    ret
.not_tty:
    lea rsi, [err_tty]
    jmp fatal
.termios_error:
    lea rsi, [err_termios]
    jmp fatal

terminal_leave:
    cmp byte [tty_active], 0
    je .done
    lea rsi, [ansi_leave]
    mov edi, 1
    call write_cstr
    xor edi, edi
    mov esi, TCSETS
    lea rdx, [orig_termios]
    mov eax, SYS_ioctl
    syscall
    mov byte [tty_active], 0
.done:
    ret

update_terminal_size:
    mov qword [term_rows], 24
    mov qword [term_cols], 80
    mov edi, 1
    mov esi, TIOCGWINSZ
    lea rdx, [winsize]
    mov eax, SYS_ioctl
    syscall
    test rax, rax
    js .done
    movzx eax, word [winsize]
    cmp rax, 12
    jae .rows_min_ok
    mov eax, 12
.rows_min_ok:
    cmp rax, MAX_ROWS
    jbe .rows_max_ok
    mov eax, MAX_ROWS
.rows_max_ok:
    mov [term_rows], rax
    movzx eax, word [winsize + 2]
    test eax, eax
    jz .done
    mov [term_cols], rax
.done:
    ret

render_screen:
    call update_terminal_size
    mov qword [out_pos], 0
    lea rsi, [ansi_home]
    call buf_puts
    call render_chrome
    movzx eax, byte [current_view]
    test eax, eax
    jz .header
    cmp eax, 1
    je .programs
    call render_sections
    jmp .flush
.programs:
    call render_programs
    jmp .flush
.header:
    call render_header
.flush:
    call buf_flush
    ret

render_chrome:
    lea rsi, [ansi_boldcyan]
    call buf_puts
    lea rsi, [title]
    call buf_puts
    lea rsi, [ansi_reset]
    call buf_puts
    lea rsi, [file_label]
    call buf_puts
    mov rsi, [file_path]
    call buf_puts
    mov al, 10
    call buf_putc

    xor r12d, r12d
.tab_loop:
    movzx eax, byte [current_view]
    cmp rax, r12
    jne .tab_plain
    lea rsi, [ansi_tab]
    call buf_puts
.tab_plain:
    cmp r12, 0
    je .tab0
    cmp r12, 1
    je .tab1
    lea rsi, [tab_sections]
    jmp .tab_write
.tab1:
    lea rsi, [tab_program]
    jmp .tab_write
.tab0:
    lea rsi, [tab_header]
.tab_write:
    call buf_puts
    lea rsi, [ansi_reset]
    call buf_puts
    inc r12
    cmp r12, 3
    jb .tab_loop
    mov al, 10
    call buf_putc
    lea rsi, [ansi_dim]
    call buf_puts
    lea rsi, [nav_hint]
    call buf_puts
    lea rsi, [ansi_reset]
    call buf_puts
    mov al, 10
    call buf_putc
    lea rsi, [line_rule]
    call buf_puts
    mov al, 10
    call buf_putc
    ret

render_header:
    mov rbx, [file_base]
    lea rsi, [hdr_title]
    call buf_puts

    lea rsi, [lbl_class]
    call buf_puts
    lea rsi, [str_elf64]
    call buf_puts_line
    lea rsi, [lbl_data]
    call buf_puts
    lea rsi, [str_little]
    call buf_puts_line
    lea rsi, [lbl_identver]
    call buf_puts
    movzx eax, byte [rbx + 6]
    call buf_put_dec_line
    lea rsi, [lbl_osabi]
    call buf_puts
    movzx edi, byte [rbx + 7]
    call osabi_name
    call buf_puts_line
    lea rsi, [lbl_abiver]
    call buf_puts
    movzx eax, byte [rbx + 8]
    call buf_put_dec_line
    lea rsi, [lbl_type]
    call buf_puts
    movzx edi, word [rbx + 16]
    call elf_type_name
    call buf_puts_line
    lea rsi, [lbl_machine]
    call buf_puts
    movzx edi, word [rbx + 18]
    call machine_name
    call buf_puts_line
    lea rsi, [lbl_entry]
    call buf_puts
    mov rax, [rbx + 24]
    call buf_put_hex_line
    lea rsi, [lbl_phoff]
    call buf_puts
    mov rax, [rbx + 32]
    call buf_put_dec_line
    lea rsi, [lbl_phnum]
    call buf_puts
    mov rax, [ph_count]
    call buf_put_dec_line
    lea rsi, [lbl_phentsize]
    call buf_puts
    movzx eax, word [rbx + 54]
    call buf_put_dec_line
    lea rsi, [lbl_shoff]
    call buf_puts
    mov rax, [rbx + 40]
    call buf_put_dec_line
    lea rsi, [lbl_shnum]
    call buf_puts
    mov rax, [sh_count]
    call buf_put_dec_line
    lea rsi, [lbl_shentsize]
    call buf_puts
    movzx eax, word [rbx + 58]
    call buf_put_dec_line
    lea rsi, [lbl_shstrndx]
    call buf_puts
    mov rax, [shstr_index]
    call buf_put_dec_line
    lea rsi, [lbl_flags]
    call buf_puts
    mov eax, dword [rbx + 48]
    call buf_put_hex_line
    lea rsi, [lbl_filesize]
    call buf_puts
    mov rax, [file_size]
    call buf_put_dec
    lea rsi, [space]
    call buf_puts
    mov al, 'B'
    call buf_putc
    mov al, 10
    call buf_putc
    ret

render_programs:
    mov r12, [ph_count]
    lea rsi, [program_title]
    call render_table_title
    test r12, r12
    jz .empty
    mov byte [wide_layout], 0
    cmp qword [term_cols], WIDE_COLS
    jb .narrow_columns
    mov byte [wide_layout], 1
    lea rsi, [program_cols]
    jmp .write_columns
.narrow_columns:
    lea rsi, [program_cols_narrow]
.write_columns:
    call buf_puts
    call table_window
    ; r13 = first row, r14 = exclusive last row
    mov r15, r13
.loop:
    cmp r15, r14
    jae .detail
    mov rax, r15
    mov rbx, [file_base]
    movzx ecx, word [rbx + 54]
    imul rax, rcx
    add rax, [rbx + 32]
    add rbx, rax

    cmp r15, [selected_row]
    jne .not_selected
    lea rsi, [ansi_select]
    call buf_puts
.not_selected:
    mov al, ' '
    call buf_putc
    mov rax, r15
    call buf_put_dec_width5
    mov edi, dword [rbx]
    call ph_type_name
    mov ecx, 11
    cmp byte [wide_layout], 0
    je .type_width_ready
    mov ecx, 13
.type_width_ready:
    call buf_puts_fixed
    mov edi, dword [rbx + 4]
    call buf_put_phflags
    mov al, ' '
    call buf_putc
    mov rax, [rbx + 8]
    call buf_put_hex
    mov al, ' '
    call buf_putc
    cmp byte [wide_layout], 0
    je .skip_vaddr
    mov rax, [rbx + 16]
    call buf_put_hex
    mov al, ' '
    call buf_putc
.skip_vaddr:
    mov rax, [rbx + 32]
    call buf_put_hex
    mov al, ' '
    call buf_putc
    mov rax, [rbx + 40]
    call buf_put_hex
    lea rsi, [ansi_reset]
    call buf_puts
    mov al, 10
    call buf_putc
    inc r15
    jmp .loop

.detail:
    mov r15, [selected_row]
    mov rax, r15
    mov rbx, [file_base]
    movzx ecx, word [rbx + 54]
    imul rax, rcx
    add rax, [rbx + 32]
    add rbx, rax
    lea rsi, [ansi_dim]
    call buf_puts
    cmp byte [wide_layout], 0
    jne .wide_detail
    lea rsi, [detail_vaddr]
    call buf_puts
    mov rax, [rbx + 16]
    call buf_put_hex
.wide_detail:
    lea rsi, [detail_paddr]
    call buf_puts
    mov rax, [rbx + 24]
    call buf_put_hex
    cmp byte [wide_layout], 0
    jne .detail_align
    mov al, 10
    call buf_putc
.detail_align:
    lea rsi, [detail_align]
    call buf_puts
    mov rax, [rbx + 48]
    call buf_put_hex
    lea rsi, [ansi_reset]
    call buf_puts
    mov al, 10
    call buf_putc
    ret
.empty:
    lea rsi, [empty_table]
    call buf_puts
    ret

render_sections:
    mov r12, [sh_count]
    lea rsi, [section_title]
    call render_table_title
    test r12, r12
    jz .empty
    mov byte [wide_layout], 0
    cmp qword [term_cols], WIDE_COLS
    jb .narrow_columns
    mov byte [wide_layout], 1
    lea rsi, [section_cols]
    jmp .write_columns
.narrow_columns:
    lea rsi, [section_cols_narrow]
.write_columns:
    call buf_puts
    call table_window
    mov r15, r13
.loop:
    cmp r15, r14
    jae .detail
    mov rax, r15
    mov rbx, [file_base]
    movzx ecx, word [rbx + 58]
    imul rax, rcx
    add rax, [rbx + 40]
    add rbx, rax

    cmp r15, [selected_row]
    jne .not_selected
    lea rsi, [ansi_select]
    call buf_puts
.not_selected:
    mov al, ' '
    call buf_putc
    mov rax, r15
    call buf_put_dec_width5
    mov edi, dword [rbx]
    mov ecx, 18
    cmp byte [wide_layout], 0
    je .name_width_ready
    mov ecx, 21
.name_width_ready:
    call buf_put_section_name
    mov edi, dword [rbx + 4]
    call sh_type_name
    mov ecx, 11
    cmp byte [wide_layout], 0
    je .type_width_ready
    mov ecx, 13
.type_width_ready:
    call buf_puts_fixed
    cmp byte [wide_layout], 0
    je .skip_address
    mov rax, [rbx + 16]
    call buf_put_hex
    mov al, ' '
    call buf_putc
.skip_address:
    mov rax, [rbx + 24]
    call buf_put_hex
    mov al, ' '
    call buf_putc
    mov rax, [rbx + 32]
    call buf_put_hex
    lea rsi, [ansi_reset]
    call buf_puts
    mov al, 10
    call buf_putc
    inc r15
    jmp .loop

.detail:
    mov r15, [selected_row]
    mov rax, r15
    mov rbx, [file_base]
    movzx ecx, word [rbx + 58]
    imul rax, rcx
    add rax, [rbx + 40]
    add rbx, rax
    lea rsi, [ansi_dim]
    call buf_puts
    cmp byte [wide_layout], 0
    jne .wide_detail
    lea rsi, [detail_address]
    call buf_puts
    mov rax, [rbx + 16]
    call buf_put_hex
    lea rsi, [detail_flags]
    call buf_puts
    mov rax, [rbx + 8]
    call buf_put_hex
    mov al, 10
    call buf_putc
.wide_detail:
    lea rsi, [detail_link]
    call buf_puts
    mov eax, dword [rbx + 40]
    call buf_put_dec
    lea rsi, [detail_info]
    call buf_puts
    mov eax, dword [rbx + 44]
    call buf_put_dec
    cmp byte [wide_layout], 0
    jne .detail_alignment
    mov al, 10
    call buf_putc
.detail_alignment:
    lea rsi, [detail_align]
    call buf_puts
    mov rax, [rbx + 48]
    call buf_put_hex
    lea rsi, [detail_entsize]
    call buf_puts
    mov rax, [rbx + 56]
    call buf_put_hex
    lea rsi, [ansi_reset]
    call buf_puts
    mov al, 10
    call buf_putc
    ret
.empty:
    lea rsi, [empty_table]
    call buf_puts
    ret

; rsi title, r12 total rows
render_table_title:
    call buf_puts
    mov al, ' '
    call buf_putc
    test r12, r12
    jz .zero
    lea rsi, [selected_lbl]
    call buf_puts
    mov rax, [selected_row]
    inc rax
    call buf_put_dec
    lea rsi, [of_lbl]
    call buf_puts
    mov rax, r12
    call buf_put_dec
.zero:
    mov al, 10
    call buf_putc
    mov al, 10
    call buf_putc
    ret

; Computes a visible table window. Uses r12 = count.
; Returns r13 = scroll start, r14 = exclusive end.
table_window:
    mov r8, [term_rows]
    sub r8, 10
    cmp r8, 1
    jae .height_ok
    mov r8, 1
.height_ok:
    mov rax, [selected_row]
    cmp rax, r12
    jb .selected_ok
    mov rax, r12
    dec rax
    mov [selected_row], rax
.selected_ok:
    mov r13, [scroll_row]
    cmp rax, r13
    jae .check_bottom
    mov r13, rax
.check_bottom:
    mov rdx, r13
    add rdx, r8
    cmp rax, rdx
    jb .scroll_ok
    mov r13, rax
    sub r13, r8
    inc r13
.scroll_ok:
    mov [scroll_row], r13
    mov r14, r13
    add r14, r8
    cmp r14, r12
    jbe .done
    mov r14, r12
.done:
    ret

; Process every byte returned by read(2). Paste/input bursts commonly contain
; several keys, so dropping everything after byte zero can leave the UI waiting
; forever after a pasted quit command. Escape sequences are consumed together.
; rsi input bytes, rdx count. Returns eax=1 to quit, otherwise 0.
handle_keys:
    mov r12, rsi
    mov r13, rdx
.loop:
    test r13, r13
    jz .done
    mov rsi, r12
    mov rdx, r13
    call handle_key
    test eax, eax
    jnz .quit

    mov r8d, 1
    cmp byte [r12], 27
    jne .advance
    cmp r13, 3
    jb .advance
    cmp byte [r12 + 1], '['
    jne .advance
    mov r8d, 3
    cmp byte [r12 + 2], '5'
    je .maybe_tilde
    cmp byte [r12 + 2], '6'
    jne .advance
.maybe_tilde:
    cmp r13, 4
    jb .advance
    cmp byte [r12 + 3], '~'
    jne .advance
    mov r8d, 4
.advance:
    add r12, r8
    sub r13, r8
    ; Make rapid key bursts observable just like individual keystrokes.
    push r12
    push r13
    call render_screen
    pop r13
    pop r12
    jmp .loop
.done:
    xor eax, eax
    ret
.quit:
    mov eax, 1
    ret

; rsi input bytes, rdx count. Returns eax=1 to quit, otherwise 0.
handle_key:
    movzx eax, byte [rsi]
    cmp al, 'q'
    je .quit
    cmp al, 'Q'
    je .quit
    cmp al, 3
    je .quit
    cmp al, 27
    je .escape
    cmp al, '1'
    je .view0
    cmp al, '2'
    je .view1
    cmp al, '3'
    je .view2
    cmp al, 9
    je .next_view
    cmp al, 'l'
    je .next_view
    cmp al, 'h'
    je .prev_view
    cmp al, 'j'
    je .down
    cmp al, 'k'
    je .up
    cmp al, 'g'
    je .first
    cmp al, 'G'
    je .last
.no_action:
    xor eax, eax
    ret

.escape:
    cmp rdx, 1
    je .quit
    cmp byte [rsi + 1], '['
    jne .quit
    cmp rdx, 3
    jb .no_action
    mov al, [rsi + 2]
    cmp al, 'A'
    je .up
    cmp al, 'B'
    je .down
    cmp al, 'C'
    je .next_view
    cmp al, 'D'
    je .prev_view
    cmp al, 'H'
    je .first
    cmp al, 'F'
    je .last
    cmp al, '5'
    je .page_up
    cmp al, '6'
    je .page_down
    jmp .no_action

.view0:
    xor eax, eax
    jmp .set_view
.view1:
    mov eax, 1
    jmp .set_view
.view2:
    mov eax, 2
.set_view:
    mov [current_view], al
    mov qword [selected_row], 0
    mov qword [scroll_row], 0
    xor eax, eax
    ret
.next_view:
    movzx eax, byte [current_view]
    inc eax
    cmp eax, 3
    jb .set_view
    xor eax, eax
    jmp .set_view
.prev_view:
    movzx eax, byte [current_view]
    test eax, eax
    jnz .prev_dec
    mov eax, 3
.prev_dec:
    dec eax
    jmp .set_view

.down:
    call current_count
    test rax, rax
    jz .no_action
    mov rcx, [selected_row]
    inc rcx
    cmp rcx, rax
    jae .no_action
    mov [selected_row], rcx
    jmp .no_action
.up:
    mov rax, [selected_row]
    test rax, rax
    jz .no_action
    dec rax
    mov [selected_row], rax
    jmp .no_action
.first:
    mov qword [selected_row], 0
    mov qword [scroll_row], 0
    jmp .no_action
.last:
    call current_count
    test rax, rax
    jz .no_action
    dec rax
    mov [selected_row], rax
    jmp .no_action
.page_up:
    mov rcx, [term_rows]
    sub rcx, 10
    cmp rcx, 1
    jae .page_up_size
    mov ecx, 1
.page_up_size:
    mov rax, [selected_row]
    cmp rax, rcx
    jae .page_up_sub
    xor eax, eax
    jmp .page_up_store
.page_up_sub:
    sub rax, rcx
.page_up_store:
    mov [selected_row], rax
    jmp .no_action
.page_down:
    call current_count
    test rax, rax
    jz .no_action
    mov rcx, [term_rows]
    sub rcx, 10
    cmp rcx, 1
    jae .page_down_size
    mov ecx, 1
.page_down_size:
    add rcx, [selected_row]
    dec rax
    cmp rcx, rax
    jbe .page_down_store
    mov rcx, rax
.page_down_store:
    mov [selected_row], rcx
    jmp .no_action
.quit:
    mov eax, 1
    ret

current_count:
    movzx eax, byte [current_view]
    cmp eax, 1
    je .ph
    cmp eax, 2
    je .sh
    xor eax, eax
    ret
.ph:
    mov rax, [ph_count]
    ret
.sh:
    mov rax, [sh_count]
    ret

; Name lookup helpers. All return rsi pointing to a trusted NUL-terminated name.
elf_type_name:
    lea rsi, [type_none]
    test edi, edi
    jz .done
    lea rsi, [type_rel]
    cmp edi, 1
    je .done
    lea rsi, [type_exec]
    cmp edi, 2
    je .done
    lea rsi, [type_dyn]
    cmp edi, 3
    je .done
    lea rsi, [type_core]
    cmp edi, 4
    je .done
    lea rsi, [unknown]
.done: ret

machine_name:
    lea rsi, [machine_none]
    test edi, edi
    jz .done
    lea rsi, [machine_x86]
    cmp edi, 3
    je .done
    lea rsi, [machine_arm]
    cmp edi, 40
    je .done
    lea rsi, [machine_x64]
    cmp edi, 62
    je .done
    lea rsi, [machine_aarch64]
    cmp edi, 183
    je .done
    lea rsi, [machine_riscv]
    cmp edi, 243
    je .done
    lea rsi, [unknown]
.done: ret

osabi_name:
    lea rsi, [osabi_sysv]
    test edi, edi
    jz .done
    lea rsi, [osabi_hpux]
    cmp edi, 1
    je .done
    lea rsi, [osabi_netbsd]
    cmp edi, 2
    je .done
    lea rsi, [osabi_linux]
    cmp edi, 3
    je .done
    lea rsi, [osabi_solaris]
    cmp edi, 6
    je .done
    lea rsi, [osabi_aix]
    cmp edi, 7
    je .done
    lea rsi, [osabi_freebsd]
    cmp edi, 9
    je .done
    lea rsi, [osabi_openbsd]
    cmp edi, 12
    je .done
    lea rsi, [unknown]
.done: ret

ph_type_name:
    lea rsi, [pt_null]
    test edi, edi
    jz .done
    lea rsi, [pt_load]
    cmp edi, 1
    je .done
    lea rsi, [pt_dynamic]
    cmp edi, 2
    je .done
    lea rsi, [pt_interp]
    cmp edi, 3
    je .done
    lea rsi, [pt_note]
    cmp edi, 4
    je .done
    lea rsi, [pt_shlib]
    cmp edi, 5
    je .done
    lea rsi, [pt_phdr]
    cmp edi, 6
    je .done
    lea rsi, [pt_tls]
    cmp edi, 7
    je .done
    lea rsi, [pt_ehframe]
    cmp edi, 0x6474e550
    je .done
    lea rsi, [pt_stack]
    cmp edi, 0x6474e551
    je .done
    lea rsi, [pt_relro]
    cmp edi, 0x6474e552
    je .done
    lea rsi, [pt_property]
    cmp edi, 0x6474e553
    je .done
    lea rsi, [unknown]
.done: ret

sh_type_name:
    lea rsi, [sht_null]
    test edi, edi
    jz .done
    lea rsi, [sht_progbits]
    cmp edi, 1
    je .done
    lea rsi, [sht_symtab]
    cmp edi, 2
    je .done
    lea rsi, [sht_strtab]
    cmp edi, 3
    je .done
    lea rsi, [sht_rela]
    cmp edi, 4
    je .done
    lea rsi, [sht_hash]
    cmp edi, 5
    je .done
    lea rsi, [sht_dynamic]
    cmp edi, 6
    je .done
    lea rsi, [sht_note]
    cmp edi, 7
    je .done
    lea rsi, [sht_nobits]
    cmp edi, 8
    je .done
    lea rsi, [sht_rel]
    cmp edi, 9
    je .done
    lea rsi, [sht_shlib]
    cmp edi, 10
    je .done
    lea rsi, [sht_dynsym]
    cmp edi, 11
    je .done
    lea rsi, [sht_init_array]
    cmp edi, 14
    je .done
    lea rsi, [sht_fini_array]
    cmp edi, 15
    je .done
    lea rsi, [sht_preinit]
    cmp edi, 16
    je .done
    lea rsi, [sht_group]
    cmp edi, 17
    je .done
    lea rsi, [sht_symtab_shndx]
    cmp edi, 18
    je .done
    lea rsi, [unknown]
.done: ret

; Buffer primitives ---------------------------------------------------------

buf_putc:
    push r10
    mov rdi, [out_pos]
    cmp rdi, OUTBUF_SIZE
    jae .done
    lea r10, [outbuf]
    mov [r10 + rdi], al
    inc rdi
    mov [out_pos], rdi
.done:
    pop r10
    ret

buf_puts:
    mov rdx, [out_pos]
    lea r10, [outbuf]
.loop:
    cmp rdx, OUTBUF_SIZE
    jae .done
    mov al, [rsi]
    test al, al
    jz .done
    mov [r10 + rdx], al
    inc rsi
    inc rdx
    jmp .loop
.done:
    mov [out_pos], rdx
    ret

buf_puts_line:
    call buf_puts
    mov al, 10
    call buf_putc
    ret

buf_put_dec_line:
    call buf_put_dec
    mov al, 10
    call buf_putc
    ret

buf_put_hex_line:
    call buf_put_hex
    mov al, 10
    call buf_putc
    ret

; rsi = trusted string, ecx = field width. Always emits exactly width bytes.
buf_puts_fixed:
    mov r8d, ecx
    xor r9d, r9d
.chars:
    cmp r9, r8
    jae .done
    mov al, [rsi]
    test al, al
    jz .pad
    call buf_putc
    inc rsi
    inc r9
    jmp .chars
.pad:
    mov al, ' '
    call buf_putc
    inc r9
    jmp .chars
.done:
    ret

; edi = offset into section-name string table, ecx = output width.
buf_put_section_name:
    mov r8d, ecx
    xor r9d, r9d
    mov r10, [shstr_base]
    test r10, r10
    jz .placeholder
    mov eax, edi
    cmp rax, [shstr_size]
    jae .placeholder
    add r10, rax
    mov r11, [shstr_base]
    add r11, [shstr_size]
.chars:
    cmp r9, r8
    jae .done
    cmp r10, r11
    jae .pad
    mov al, [r10]
    test al, al
    jz .pad
    cmp al, 32
    jb .sanitize
    cmp al, 126
    jbe .emit
.sanitize:
    mov al, '?'
.emit:
    call buf_putc
    inc r10
    inc r9
    jmp .chars
.placeholder:
    lea rsi, [placeholder]
    mov ecx, r8d
    jmp buf_puts_fixed
.pad:
    mov al, ' '
    call buf_putc
    inc r9
    jmp .chars
.done:
    ret

buf_put_dec:
    sub rsp, 32
    xor r8d, r8d
    mov ecx, 10
    test rax, rax
    jnz .convert
    mov al, '0'
    call buf_putc
    add rsp, 32
    ret
.convert:
    xor edx, edx
    div rcx
    add dl, '0'
    mov [rsp + r8], dl
    inc r8
    test rax, rax
    jnz .convert
.emit:
    dec r8
    mov al, [rsp + r8]
    call buf_putc
    test r8, r8
    jnz .emit
    add rsp, 32
    ret

buf_put_dec_width5:
    ; Table indices are bounded by file size, so 20 decimal digits is enough.
    sub rsp, 32
    xor r8d, r8d
    mov ecx, 10
    test rax, rax
    jnz .convert
    mov byte [rsp], '0'
    mov r8d, 1
    jmp .pad
.convert:
    xor edx, edx
    div rcx
    add dl, '0'
    mov [rsp + r8], dl
    inc r8
    test rax, rax
    jnz .convert
.pad:
    mov r9d, 5
    cmp r8, r9
    jae .emit
    sub r9, r8
.pad_loop:
    mov al, ' '
    call buf_putc
    dec r9
    jnz .pad_loop
.emit:
    dec r8
    mov al, [rsp + r8]
    call buf_putc
    test r8, r8
    jnz .emit
    mov al, ' '
    call buf_putc
    add rsp, 32
    ret

; Fixed 16-digit hexadecimal keeps table columns stable.
buf_put_hex:
    mov r8, rax
    mov al, '0'
    call buf_putc
    mov al, 'x'
    call buf_putc
    mov ecx, 60
.loop:
    mov rdx, r8
    shr rdx, cl
    and edx, 15
    lea rsi, [hex_digits]
    mov al, [rsi + rdx]
    call buf_putc
    sub ecx, 4
    jns .loop
    ret

; edi = ELF p_flags. Emits a four-character field: RWE plus space.
buf_put_phflags:
    mov r8d, edi
    mov al, '-'
    test r8d, 4
    jz .r
    mov al, 'R'
.r: call buf_putc
    mov al, '-'
    test r8d, 2
    jz .w
    mov al, 'W'
.w: call buf_putc
    mov al, '-'
    test r8d, 1
    jz .x
    mov al, 'E'
.x: call buf_putc
    mov al, ' '
    call buf_putc
    ret

buf_flush:
    xor r8d, r8d
    mov r9, [out_pos]
.loop:
    cmp r8, r9
    jae .done
    mov edi, 1
    lea rsi, [outbuf]
    add rsi, r8
    mov rdx, r9
    sub rdx, r8
    mov eax, SYS_write
    syscall
    test rax, rax
    jle .done
    add r8, rax
    jmp .loop
.done:
    ret

; Generic process helpers ---------------------------------------------------

; rdi fd, rsi NUL-terminated bytes
write_cstr:
    mov r8, rdi
    mov rdx, rsi
.scan:
    cmp byte [rdx], 0
    je .write
    inc rdx
    jmp .scan
.write:
    sub rdx, rsi
    mov rdi, r8
    mov eax, SYS_write
    syscall
    ret

; rdi/rsi strings. eax=0 equal, eax=1 different.
streq:
.loop:
    mov al, [rdi]
    cmp al, [rsi]
    jne .different
    test al, al
    jz .equal
    inc rdi
    inc rsi
    jmp .loop
.different:
    mov eax, 1
    ret
.equal:
    xor eax, eax
    ret

; rsi = error message, does not return.
fatal:
    push rsi
    cmp byte [tty_active], 0
    je .print
    call terminal_leave
.print:
    lea rsi, [err_prefix]
    mov edi, 2
    call write_cstr
    pop rsi
    mov edi, 2
    call write_cstr
    lea rsi, [newline]
    mov edi, 2
    call write_cstr
    mov edi, 1
    mov eax, SYS_exit
    syscall
