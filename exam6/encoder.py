#!/usr/bin/env python
import sys

#if len(sys.argv) < 2:
#	sys.exit('Usage: %s \\xshellcode' % sys.argv[0])

#s=sys.argv[1]

s='\x31\xc0\x31\xdb\x31\xd2\xb0\x04\xb3\x01\x68\x65\x72\x65\x0a\x68\x48\x69\x54\x68\x89\xe1\xb2\x08\xcd\x80\x31\xdb\xb0\x01\xcd\x80'
e=[]

print "Encoded shellcode"
for i in range(len(s)):
	e=(int(s[i].encode('hex'),16) ^ 0x5)
	print '\\x%0.2x' % e,
	sys.stdout.write('')

print ""
