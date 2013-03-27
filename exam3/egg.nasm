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
; Filename: egg.nasm
; Author: Andrey Arapov <andrey.arapov@gmail.com>
; 2013 March
;
;

section .text
global _start

_start:
	;db "Egg-Mark"	; QWORD egg marker - will be appended in shellcode.c after running 'make.sh'

	; loop counter = 8
	xor ecx, ecx
	mov cl, 8
decloop:
	dec eax
	loop decloop
