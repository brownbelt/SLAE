#!/usr/bin/env python
import sys

#if len(sys.argv) < 2:
#	sys.exit('Usage: %s \\xshellcode' % sys.argv[0])

#s=sys.argv[1]

s='\x34\xc5\x34\xde\x34\xd7\xb5\x01\xb6\x04\x6d\x60\x77\x60\x0f\x6d\x4d\x6c\x51\x6d\x8c\xe4\xb7\x0d\xc8\x85\x34\xde\xb5\x04\xc8\x85'
e=[]

print "Decoded shellcode"
for i in range(len(s)):
	e=(int(s[i].encode('hex'),16) ^ 0x5)
	print '\\x%0.2x' % e,
	sys.stdout.write('')

print ""
