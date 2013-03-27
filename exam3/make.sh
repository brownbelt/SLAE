#!/usr/bin/env sh
#
# USAGE
# ./make.sh [Egg-Mark]
#
# NOTE
# Egg-Mark must be a plaintext with 8 bytes in length
# If Egg-Mark was not specified, the default one will be used.
#
# To specify a custom payload, simply modify the code of payload.nasm file.
# Alternativly, you can modify PAYLOADCODE= variable down below the code.
#

ARG1=$1

if [ -z "$ARG1" ]; then
  echo " [I] Argument not specified. Using default EGG mark."
  ARG1="Egg-Mark";
elif ! [[ `expr length $ARG1` -ge 8 && `expr length $ARG1` -le 8 ]]; then
  echo " [E] Custom EGG mark must be 8 bytes in length! Exiting."
  exit 1;
else
  echo " [I] Using custom EGG mark: "$ARG1
fi


DEFAULTEGG=($(echo -n "Egg-Mark" | sed -e 's/\(....\)/\1\n/g'))		# set in hunter.nasm
EGGMARK=$ARG1
NEWEGG=($(echo -n $EGGMARK | sed -e 's/\(....\)/\1\n/g'))

# Uncomment to save EGGMARK in HEX
EGGMARK=$(echo -n $ARG1 | od -A n -t x1 |sed 's/ /\\x/g')

# Cleanup
rm -f shellcode payload.o payload hunter.o hunter

echo " [+] Compiling payload.nasm ..."
nasm -f elf32 -o payload.o payload.nasm
ld -m elf_i386 -o payload payload.o

echo " [+] Compiling hunter.nasm ..."
nasm -f elf32 -o hunter.o hunter.nasm
ld -m elf_i386 -o hunter hunter.o

echo " [+] Extracting PAYLOAD code from payload ..."
PAYLOADCODE=$(objdump -d ./payload |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s)

echo " [+] Adding EGG mark to PAYLOAD ..."
FULL_PAYLOADCODE=$(echo -n ${EGGMARK}${PAYLOADCODE}|sed 's/^/"/' |sed 's/$/"/g')

echo " [+] Checking PAYLOAD code for NULLs ..."
if [[ $FULL_PAYLOADCODE == *00* ]]; then
  echo " [E] Your PAYLOAD code contains 00 (NULL) ! Exiting."
  exit 1
fi


echo " [+] Extracting HUNTER code from hunter ..."
HUNTERCODE=$(objdump -d ./hunter |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s|sed 's/^/"/' |sed 's/$/"/g')

# For debugging only
#echo ${DEFAULTEGG[0]}
#echo ${DEFAULTEGG[1]}
#echo ${NEWEGG[0]}
#echo ${NEWEGG[1]}

# Preparing Default egg to HEX form in order to replace it with a New egg
DEFEGG1=$(echo -n ${DEFAULTEGG[0]} | od -A n -t x1 |sed 's/ /\\x/g'|sed 's/\\/\\\\/g')
DEFEGG2=$(echo -n ${DEFAULTEGG[1]} | od -A n -t x1 |sed 's/ /\\x/g'|sed 's/\\/\\\\/g')

# Uncomment to save new EGGMARK in HEX format
NEWEGG1=$(echo -n ${NEWEGG[0]} | od -A n -t x1 |sed 's/ /\\x/g'|sed 's/\\/\\\\/g')
NEWEGG2=$(echo -n ${NEWEGG[1]} | od -A n -t x1 |sed 's/ /\\x/g'|sed 's/\\/\\\\/g')

# Uncomment to save new EGGMARK in Plaintext format
#NEWEGG1=$(echo -n ${NEWEGG[0]})
#NEWEGG2=$(echo -n ${NEWEGG[1]})


FULL_HUNTERCODE=$(echo -n $HUNTERCODE |sed 's/'$DEFEGG1'/'$NEWEGG1'/g'| sed 's/'$DEFEGG2'/'$NEWEGG2'/g')

echo " [+] Checking HUNTER code for NULLs ..."
if [[ $FULL_HUNTERCODE == *00* ]]; then
  echo " [E] Your HUNTER code contains 00 (NULL) ! Exiting."
  exit 1
fi


# Uncomment to see what will is replaced (default egg with a new one)
#echo $DEFEGG1
#echo $DEFEGG2
#echo $NEWEGG1
#echo $NEWEGG2
#echo $HUNTERCODE
#echo $FULL_HUNTERCODE

cat > shellcode.c << EOF
#include <stdio.h>
#include <string.h>

unsigned char hunter[] = \
$FULL_HUNTERCODE;

unsigned char garbage1[] = \
"Just some garbage here...";

unsigned char payload[] = \
$FULL_PAYLOADCODE;

unsigned char garbage2[] = \
"And some garbage there...";

main()
{
	printf("Hunter Length:  %d\n", strlen(hunter));
	printf("Payload Length:  %d\n", strlen(payload));
	int (*ret)() = (int(*)())hunter;
	ret();
}
EOF

echo " [+] Compiling shellcode.c ..."
gcc -m32 -fno-stack-protector -z execstack shellcode.c -o shellcode

# Cleanup
rm -f payload.o payload hunter.o hunter

ls -la ./shellcode

echo " [+] All done!"
