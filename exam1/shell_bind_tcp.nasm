; Filename: shell_bind_tcp.nasm
; Author: Andrey Arapov <andrey.arapov@gmail.com>
; 2013 March

global _start


section .text

_start:

	xor eax, eax	; EAX = 0x000000
	mov al, 1	; EAX = 0x000001	__NR_exit 1:/usr/include/asm/unistd_32.h

	xor ebx, ebx	; EBX = 0x000000	0: success status
	int 0x80


;section .data
