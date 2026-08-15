#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
bin="$root/elfscope"
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT HUP INT TERM

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

"$bin" --help | grep -q "Usage: elfscope" || fail "help output"
"$bin" --version | grep -q "elfscope 0.1.0" || fail "version output"

printf 'not an elf\n' >"$tmpdir/not-elf"
if "$bin" "$tmpdir/not-elf" >"$tmpdir/out" 2>"$tmpdir/err"; then
    fail "invalid file was accepted"
fi
grep -q "too small" "$tmpdir/err" || fail "short-file diagnostic"

cp "$bin" "$tmpdir/wrong-class"
printf '\001' | dd of="$tmpdir/wrong-class" bs=1 seek=4 conv=notrunc status=none
if "$bin" "$tmpdir/wrong-class" >"$tmpdir/out" 2>"$tmpdir/err"; then
    fail "ELF32 file was accepted"
fi
grep -q "only 64-bit" "$tmpdir/err" || fail "class diagnostic"

cp "$bin" "$tmpdir/wrong-endian"
printf '\002' | dd of="$tmpdir/wrong-endian" bs=1 seek=5 conv=notrunc status=none
if "$bin" "$tmpdir/wrong-endian" >"$tmpdir/out" 2>"$tmpdir/err"; then
    fail "big-endian file was accepted"
fi
grep -q "little-endian" "$tmpdir/err" || fail "encoding diagnostic"

cp "$bin" "$tmpdir/truncated"
truncate -s 80 "$tmpdir/truncated"
if "$bin" "$tmpdir/truncated" >"$tmpdir/out" 2>"$tmpdir/err"; then
    fail "truncated ELF was accepted"
fi
grep -Eq "table is truncated|invalid ELF" "$tmpdir/err" || fail "truncation diagnostic"

cp "$bin" "$tmpdir/bad-phoff"
printf '\377\377\377\377\377\377\377\177' |
    dd of="$tmpdir/bad-phoff" bs=1 seek=32 conv=notrunc status=none
if "$bin" "$tmpdir/bad-phoff" >"$tmpdir/out" 2>"$tmpdir/err"; then
    fail "out-of-bounds program table was accepted"
fi
grep -q "program header table" "$tmpdir/err" || fail "program-table diagnostic"

cp "$bin" "$tmpdir/bad-shoff"
printf '\377\377\377\377\377\377\377\177' |
    dd of="$tmpdir/bad-shoff" bs=1 seek=40 conv=notrunc status=none
if "$bin" "$tmpdir/bad-shoff" >"$tmpdir/out" 2>"$tmpdir/err"; then
    fail "out-of-bounds section table was accepted"
fi
grep -q "section header table" "$tmpdir/err" || fail "section-table diagnostic"

if command -v script >/dev/null 2>&1; then
    printf '23jk1q' | script -qfec "$bin $bin" "$tmpdir/typescript" >/dev/null
    grep -q "ELFSCOPE" "$tmpdir/typescript" || fail "TUI title"
    grep -q "Program Headers" "$tmpdir/typescript" || fail "program-header view"
    grep -q "Section Headers" "$tmpdir/typescript" || fail "section-header view"
    grep -q "Selected 2 of" "$tmpdir/typescript" || fail "row navigation"
    grep -q "\.text" "$tmpdir/typescript" || fail "section-name lookup"
    grep -q "R-E" "$tmpdir/typescript" || fail "program flags"
fi

echo "smoke tests passed"
