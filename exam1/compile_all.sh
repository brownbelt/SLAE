#!/usr/bin/env sh
#
# Create shellcode with specific port
#
# Example
# ./compile_all.sh shell_bind_tcp 50123
#
# If no port specified, the default one will be used 43775
#
# Port is stored in last two bytes in HEX
#

ARG1=$1        # Specify program
ARG2=$2        # Specify port


if [ -z "$ARG1" ]; then
  echo " [I] Please specify program you would like to assemble!"
  echo " [I] Usage example: ./compile_all.sh shell_bind_tcp 50123"
  exit 1;
elif ! [ -e "$ARG1".nasm ]; then
  ARG1_GUESS=$(echo $ARG1 |sed 's/.nasm//g')
  if [ -e "$ARG1_GUESS" ]; then
    ARG1=$ARG1_GUESS
  else
    echo " [E] File "$ARG1".nasm does not exist!"
    exit 1;
  fi
fi

if ! $(grep -qi ^global $ARG1.nasm 2>/dev/null); then
  echo " [E] The file "$ARG1.nasm" does not appear to be a correct NASM source!"
  exit 1;
fi

if [ -z "$ARG2" ]; then
  echo " [I] Default port will be used."
elif ! [[ $ARG2 -ge 1024 && $ARG2 -le 65535 ]]; then
  echo " [E] The port must be in range 1024..65535 !"
  exit 1;
else
  echo " [I] Using custom port: "$ARG2
fi

echo " [+] Assembling "$1".nasm with NASM ..."
nasm -f elf32 -o $ARG1.o $ARG1.nasm && \
echo " [+] Linking "$1".o ..." && \
ld -m elf_i386 -o $ARG1 $ARG1.o && \
echo -e " [+] Generating shellcode with objdump ..." && \
SHELLCODE=$(objdump -d ./$ARG1 |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/' |sed 's/$/"/g')

if [ -z "$ARG2" ]; then
  FULL_SHELLCODE=$(echo $SHELLCODE)
else
  PORT_HEX=$(printf '%.4x' $ARG2 | sed 's/../\\x&/g')
  FULL_SHELLCODE=$(echo -n $SHELLCODE | sed 's/.........$//' ; echo $PORT_HEX"\"")
fi

if [[ $FULL_SHELLCODE == *00* ]]; then
  echo " [E] Your shellcode contains 00 (NULL) ! Most likely you need to change your port."
  exit 1
fi

echo -ne " [+] Shellcode size is "$(echo -ne $FULL_SHELLCODE|sed 's/\"//g'|wc -c)" bytes\n"
echo $FULL_SHELLCODE


echo " [+] Generating shellcode.c file with the "$ARG1" shellcode ..."
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

echo " [+] Compiling shellcode.c with GCC ..."
gcc -m32 -fno-stack-protector -z execstack shellcode.c -o shellcode

echo -e " [+] All done! You can run the shellcode now: \n$ ./shellcode"
