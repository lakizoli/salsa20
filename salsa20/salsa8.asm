.data
; caption db '64-bit hello!', 0
; message db 'Hello World!', 0


.code

; ********************************************************************************
; First step of salsa8 calculation (xor input and output for all threads)
; ********************************************************************************

PUBLIC asm_salsa8_parallel_xor
asm_salsa8_parallel_xor PROC
  sub		rsp,28h      ; shadow space, aligns stack

  mov		r8, rcx
  mov		rcx, 8
  mov		r9, 0
  
step_xor:
  vmovdqu	ymm0,ymmword ptr [r8 + r9]
  vpxor		ymm4,ymm0,ymmword ptr [rdx + r9]
  vmovdqu	ymmword ptr [rdx + r9],ymm4

  add		r9, 20h
  vmovdqu	ymm1,ymmword ptr [r8 + r9]
  vpxor		ymm5,ymm1,ymmword ptr [rdx + r9]
  vmovdqu	ymmword ptr [rdx + r9],ymm5
  
  add		r9, 60h
  loop		step_xor

  add		rsp, 28h
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