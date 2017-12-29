.data
; caption db '64-bit hello!', 0
; message db 'Hello World!', 0


.code

; ********************************************************************************
; First step of salsa8 calculation (xor input and output for all threads)
; input params:
;    rcx: address of input array (16 x uint32_t for each (8) thread)
;    rdx: address of output array (16 x uint32_t for each (8) thread)
; locally used registers:
;    rax: input address
;    r8, r10: byte offset in input and output array (first part of a thread's 16x uint32_t)
;    r9, r11: byte offset in input and output array (second part of a thread's 16x uint32_t)
;    rcx: loop counter (thread count/2 - calculate two thread in one loop)
;    ymm0..3: calculation helpers
; ********************************************************************************

PUBLIC asm_salsa8_parallel_xor
asm_salsa8_parallel_xor PROC

input				EQU rax
output				EQU rdx
offset_th1_low		EQU r8
offset_th1_high		EQU r9
offset_th2_low		EQU r10
offset_th2_high		EQU r11

  mov		input, rcx				;preserve input array's address
  mov		rcx, 4					;two thread in one loop!

  mov		offset_th1_low, 0
  mov		offset_th1_high, 20h
  mov		offset_th2_low, 80h
  mov		offset_th2_high, 0A0h
  
step_xor:
  vmovdqa	ymm0, ymmword ptr [input + offset_th1_low]
  vmovdqa	ymm1, ymmword ptr [input + offset_th1_high]
  vmovdqa	ymm2, ymmword ptr [input + offset_th2_low]
  vmovdqa	ymm3, ymmword ptr [input + offset_th2_high]

  vpxor		ymm4, ymm0, ymmword ptr [output + offset_th1_low]
  vpxor		ymm5, ymm1, ymmword ptr [output + offset_th1_high]
  vpxor		ymm0, ymm2, ymmword ptr [output + offset_th2_low]
  vpxor		ymm1, ymm3, ymmword ptr [output + offset_th2_high]

  vmovdqa	ymmword ptr [output + offset_th1_low], ymm4
  vmovdqa	ymmword ptr [output + offset_th1_high], ymm5
  vmovdqa	ymmword ptr [output + offset_th2_low], ymm0
  vmovdqa	ymmword ptr [output + offset_th2_high], ymm1
  
  add		offset_th1_low, 100h
  add		offset_th1_high, 100h
  add		offset_th2_low, 100h
  add		offset_th2_high, 100h

  loop		step_xor

  ret
asm_salsa8_parallel_xor ENDP

; ********************************************************************************
; Second step of salsa8 calculation (transpose output for all threads to prepare the parallel salsa8 calculation)
; input params:
;    rcx: address of output array (16 x uint32_t for each (8) thread)
;    rdx: address of calcX array (16 x uint32_t for each (8) thread)
; locally used registers:
;    rax: output address
;    r8: byte offset in output array
;    r9: byte offset in calcX array
;    rcx: loop counter (thread count/2 - calculate two thread in one loop)
;    ymm0..3: calculation helpers
; ********************************************************************************
.data

gather_offset dd 0, 20h, 40h, 60h, 80h, 0A0h, 0C0h, 0E0h

.code

PUBLIC asm_salsa8_parallel_gather
asm_salsa8_parallel_gather PROC

output			EQU rax
calcX			EQU rdx
output_pos		EQU r8
calcX_pos		EQU r9

  mov			output, rcx				;preserve output array's address
  mov			rcx, 8
  mov			output_pos, output
  mov			calcX_pos, calcX
  vmovdqu		ymm0, ymmword ptr [gather_offset]

step_gather:
  vpcmpeqb		ymm1, ymm1, ymm1
  vpcmpeqb		ymm3, ymm3, ymm3
  vpgatherdd  	ymm2, dword ptr [output_pos + ymm0*4 + 0h], ymm1
  vpgatherdd  	ymm4, dword ptr [output_pos + ymm0*4 + 4h], ymm3
  vmovdqa		ymmword ptr [calcX_pos + 0h], ymm2
  vmovdqa		ymmword ptr [calcX_pos + 20h], ymm4

  add			output_pos, 8h
  add			calcX_pos, 40h

  loop			step_gather

  ret
asm_salsa8_parallel_gather ENDP



; ********************************************************************************
; Postprocess of salsa8 calculation (transpose back output and do some addition for all threads to close the parallel salsa8 calculation)
; input params:
;    rcx: address of calcX array (16 x uint32_t for each (8) thread)
;    rdx: address of output array (16 x uint32_t for each (8) thread)
; locally used registers:
;    rax: calcX address
;    r8: byte offset in output array
;    r9: byte offset in calcX array
;    rcx: loop counter (thread count/2 - calculate two thread in one loop)
;    ymm0..3: calculation helpers
; ********************************************************************************
.data

close_gather_offset dd 0, 8, 16, 24, 32, 40, 48, 56

.code

PUBLIC asm_salsa8_parallel_postprocess
asm_salsa8_parallel_postprocess PROC

output			EQU rdx
calcX			EQU rax
output_pos		EQU r8
calcX_pos		EQU r9

  mov			calcX, rcx				;preserve calcX array's address
  mov			rcx, 8
  mov			output_pos, output
  mov			calcX_pos, calcX
  vmovdqu		ymm0, ymmword ptr [close_gather_offset]

step_post:
  vpcmpeqb		ymm1, ymm1, ymm1
  vpcmpeqb		ymm3, ymm3, ymm3
  vpgatherdd  	ymm2, dword ptr [calcX_pos + ymm0*4 + 0h], ymm1
  vpgatherdd  	ymm4, dword ptr [calcX_pos + ymm0*4 + 100h], ymm3
  vpaddd		ymm1, ymm2, dword ptr [output_pos + 0h]
  vpaddd		ymm3, ymm4, dword ptr [output_pos + 20h]
  vmovdqa		ymmword ptr [output_pos + 0h], ymm1
  vmovdqa		ymmword ptr [output_pos + 20h], ymm3

  add			calcX_pos, 4h
  add			output_pos, 80h

  loop			step_post

  ret
asm_salsa8_parallel_postprocess ENDP


End