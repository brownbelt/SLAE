#!/usr/bin/env sh
#
# This script will generate shellcode.c and compile it
#

#
# Compile the payload and decoder
#
echo " [+] Compiling the payload and decoder ..."
SPAYLOAD=./execve-stack
nasm -f elf32 -o $SPAYLOAD.o $SPAYLOAD.nasm && ld -m elf_i386 -o $SPAYLOAD $SPAYLOAD.o
SDECODER=./decoder
nasm -f elf32 -o $SDECODER.o $SDECODER.nasm && ld -m elf_i386 -o $SDECODER $SDECODER.o

echo " [+] Preparing decoder shellcode ..."
DECODERSHELLCODE=$(echo -n "\""; for i in $(objdump -d $SDECODER -M intel |grep "^ " |cut -f2); do echo -n '\x'$i; done)

#
# Encode the payload shellcode
#
echo " [+] Encoding the payload shellcode ..."
#
#  $ echo -en '\x37\xFA\xD6\x3F' |ndisasm -b32 -
#  00000000  37                aaa
#  00000001  FA                cli
#  00000002  D6                salc
#  00000003  3F                aas
#

# Permutation code
garbage=('\x37' '\xFA' '\xD6' '\x3F');
#ENCPSHELLCODE=$(for i in $(objdump -d $SPAYLOAD |grep "^ " |cut -f2); do echo -n '\x'$i;  echo -n ${garbage[$[$(shuf --random-source=/dev/urandom -z -i 999-999999 -n1)%4]]}; done; echo -n "\xAF\"")
ENCPSHELLCODE=$(for i in $(objdump -d $SPAYLOAD |grep "^ " |cut -f2); do echo -n '\x'$i;  echo -n ${garbage[$[$(od -A n -N 2 -t u2 /dev/urandom)%4]]}; done; echo -n "\xAF\"")


FULL_SHELLCODE=${DECODERSHELLCODE}${ENCPSHELLCODE}

#
# Generate shellcode.c
#
echo " [+] Generating shellcode.c file ..."
cat > shellcode.c << EOF
#include <stdio.h>
#include <string.h>

unsigned char code[] = \
$FULL_SHELLCODE;

main()
{
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}
EOF

#
# Compile C code with GCC
#
echo " [+] Compiling shellcode.c with GCC ..."
gcc -m32 -fno-stack-protector -z execstack shellcode.c -o shellcode

ls -la ./shellcode

#
# Cleanup
#
rm ./$SPAYLOAD ./$SDECODER ./$SPAYLOAD.o ./$SDECODER.o

