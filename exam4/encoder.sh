#!/usr/bin/env sh

echo "Original shellcode"
for i in $(objdump -d helloworld -M intel |grep "^ " |cut -f2); do echo -n '\x'$i; done; echo

echo ""


echo "Encoded shellcode"
Y=2; for i in $(objdump -d helloworld -M intel |grep "^ " |cut -f2); do echo -n '\x'$i; if [[ $Y -gt 1 ]];then echo -n '\xAA'; Y=$[Y-1]; else Y=$[Y+1]; fi; done; echo

echo ""

