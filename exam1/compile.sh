#!/usr/bin/env sh
ARG1=$1
set -x
nasm -f elf32 -o $ARG1.o $ARG1.nasm && ld -m elf_i386 -o $ARG1 $ARG1.o

