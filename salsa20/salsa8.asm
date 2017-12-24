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
;    r8: input address
;    r9: byte offset in input and output array
;    rcx: loop counter (thread count)
;    ymm0, ymm1: calculation helpers
; ********************************************************************************

PUBLIC asm_salsa8_parallel_xor
asm_salsa8_parallel_xor PROC
  mov		r8, rcx
  mov		rcx, 8
  mov		r9, 0
  
step_xor:
  vmovdqu	ymm0, ymmword ptr [r8 + r9]
  vpxor		ymm1, ymm0, ymmword ptr [rdx + r9]
  vmovdqu	ymmword ptr [rdx + r9], ymm1

  add		r9, 20h
  vmovdqu	ymm0, ymmword ptr [r8 + r9]
  vpxor		ymm1, ymm0, ymmword ptr [rdx + r9]
  vmovdqu	ymmword ptr [rdx + r9], ymm1
  
  add		r9, 60h
  loop		step_xor

  ret
asm_salsa8_parallel_xor ENDP



PUBLIC asm_salsa8_parallel_gather
asm_salsa8_parallel_gather PROC
  sub		rsp,28h      ; shadow space, aligns stack

;gather
  ; mov			r9, 0
  
; step_gather:
  ; vpcmpeqb		ymm0,ymm0,ymm0  
  ; vmovdqu     	ymmword ptr [r10 + ],ymm1  
  ; vpgatherdd  	ymm1,dword ptr [rbx+ymm2*4+4],ymm0 

  add		rsp, 28h
  ret
asm_salsa8_parallel_gather ENDP



End