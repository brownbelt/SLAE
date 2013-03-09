#!/usr/bin/env sh
ARG1=$1
set -x
nasm -f elf32 -o $ARG1.o $ARG1.nasm && ld -m elf_i386 -o $ARG1 $ARG1.o \
&& set +x && echo "Shellcode: " && objdump -d ./$1 |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

