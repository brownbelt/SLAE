; helloworld.nasm
; 2013 April
;

section .text
global _start

_start:
	xor eax,eax
	xor ebx,ebx
	xor edx,edx

	; write('hi there')
	mov al,4		; write
	mov bl,1		; stdout
	push 0x0a657265		; 'ere\n' in reverse
	push 0x68546948		; 'HiTh' in reverse
	mov ecx, esp		; ecx is a pointer to stack
	mov dl, 8		; length of message
	int 0x80

	; exit(0)
	xor ebx,ebx
	mov al,1		; exit
	int 0x80
