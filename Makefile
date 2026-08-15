NASM ?= nasm
LD ?= ld

TARGET := elfscope
OBJ := build/elfscope.o
SRC := src/elfscope.asm

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJ)
	$(LD) -o $@ $<

$(OBJ): $(SRC) | build
	$(NASM) -f elf64 -g -F dwarf -Wall -w-reloc-rel-dword -o $@ $<

build:
	mkdir -p $@

test: $(TARGET)
	./tests/smoke.sh

clean:
	rm -f $(TARGET) $(OBJ)
