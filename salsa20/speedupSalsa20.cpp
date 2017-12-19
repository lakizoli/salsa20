#define _CRT_SECURE_NO_WARNINGS

#include <stdint.h>
#include <intrin.h>
#include <cstring>
#include <cassert>
#include <cstdio>

#define ALIGN_PREFIX(x) __declspec(align(x))
#define ALIGN_POSTFIX(x)

#define SCRYPT_STEP_COUNT 1

static inline uint32_t swab32 (uint32_t v) {
	return _byteswap_ulong (v);
}

extern "C" {
	void sha256_init (uint32_t *state);
	void sha256_transform (uint32_t *state, const uint32_t *block, int swap);
}

static const uint32_t keypad[12] = {
	0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000280
};
static const uint32_t innerpad[11] = {
	0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x000004a0
};
static const uint32_t outerpad[8] = {
	0x80000000, 0, 0, 0, 0, 0, 0, 0x00000300
};
static const uint32_t finalblk[16] = {
	0x00000001, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000620
};

static void HMAC_SHA256_80_init (const uint32_t *key,
	uint32_t *tstate, uint32_t *ostate) {
	uint32_t ihash[8];
	uint32_t pad[16];
	int i;

	/* tstate is assumed to contain the midstate of key */
	memcpy (pad, key + 16, 16);
	memcpy (pad + 4, keypad, 48);
	sha256_transform (tstate, pad, 0);
	memcpy (ihash, tstate, 32);

	sha256_init (ostate);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for (; i < 16; i++)
		pad[i] = 0x5c5c5c5c;
	sha256_transform (ostate, pad, 0);

	sha256_init (tstate);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x36363636;
	for (; i < 16; i++)
		pad[i] = 0x36363636;
	sha256_transform (tstate, pad, 0);
}

static void PBKDF2_SHA256_80_128 (const uint32_t *tstate,
	const uint32_t *ostate, const uint32_t *salt, uint32_t *output) {
	uint32_t istate[8], ostate2[8];
	uint32_t ibuf[16], obuf[16];
	int i, j;

	memcpy (istate, tstate, 32);
	sha256_transform (istate, salt, 0);

	memcpy (ibuf, salt + 16, 16);
	memcpy (ibuf + 5, innerpad, 44);
	memcpy (obuf + 8, outerpad, 32);

	for (i = 0; i < 4; i++) {
		memcpy (obuf, istate, 32);
		ibuf[4] = i + 1;
		sha256_transform (obuf, ibuf, 0);

		memcpy (ostate2, ostate, 32);
		sha256_transform (ostate2, obuf, 0);
		for (j = 0; j < 8; j++)
			output[8 * i + j] = swab32 (ostate2[j]);
	}
}

static void PBKDF2_SHA256_128_32 (uint32_t *tstate, uint32_t *ostate,
	const uint32_t *salt, uint32_t *output) {
	uint32_t buf[16];
	int i;

	sha256_transform (tstate, salt, 1);
	sha256_transform (tstate, salt + 16, 1);
	sha256_transform (tstate, finalblk, 0);
	memcpy (buf, tstate, 32);
	memcpy (buf + 8, outerpad, 32);

	sha256_transform (ostate, buf, 0);
	for (i = 0; i < 8; i++)
		output[i] = swab32 (ostate[i]);
}

static void xor_salsa8 (__m256i input0, __m256i input1, __m256i& output0, __m256i& output1) {
	__m256i x0 = output0 = _mm256_xor_si256 (output0, input0);
	__m256i x1 = output1 = _mm256_xor_si256 (output1, input1);

#define x00 x0.m256i_u32[0]
#define x01 x0.m256i_u32[1]
#define x02 x0.m256i_u32[2]
#define x03 x0.m256i_u32[3]
#define x04 x0.m256i_u32[4]
#define x05 x0.m256i_u32[5]
#define x06 x0.m256i_u32[6]
#define x07 x0.m256i_u32[7]

#define x08 x1.m256i_u32[0]
#define x09 x1.m256i_u32[1]
#define x10 x1.m256i_u32[2]
#define x11 x1.m256i_u32[3]
#define x12 x1.m256i_u32[4]
#define x13 x1.m256i_u32[5]
#define x14 x1.m256i_u32[6]
#define x15 x1.m256i_u32[7]

#define SALSA_STEP {																				 \
		x04 ^= _rorx_u32 (x00 + x12, 32 - 7);	x09 ^= _rorx_u32 (x05 + x01, 32 - 7);				 \
		x14 ^= _rorx_u32 (x10 + x06, 32 - 7);	x03 ^= _rorx_u32 (x15 + x11, 32 - 7);				 \
		x08 ^= _rorx_u32 (x04 + x00, 32 - 9);	x13 ^= _rorx_u32 (x09 + x05, 32 - 9);				 \
		x02 ^= _rorx_u32 (x14 + x10, 32 - 9);	x07 ^= _rorx_u32 (x03 + x15, 32 - 9);				 \
		x12 ^= _rorx_u32 (x08 + x04, 32 - 13);	x01 ^= _rorx_u32 (x13 + x09, 32 - 13);				 \
		x06 ^= _rorx_u32 (x02 + x14, 32 - 13);	x11 ^= _rorx_u32 (x07 + x03, 32 - 13);				 \
		x00 ^= _rorx_u32 (x12 + x08, 32 - 18);	x05 ^= _rorx_u32 (x01 + x13, 32 - 18);				 \
		x10 ^= _rorx_u32 (x06 + x02, 32 - 18);	x15 ^= _rorx_u32 (x11 + x07, 32 - 18);				 \
																									 \
		x01 ^= _rorx_u32 (x00 + x03, 32 - 7);	x06 ^= _rorx_u32 (x05 + x04, 32 - 7);				 \
		x11 ^= _rorx_u32 (x10 + x09, 32 - 7);	x12 ^= _rorx_u32 (x15 + x14, 32 - 7);				 \
		x02 ^= _rorx_u32 (x01 + x00, 32 - 9);	x07 ^= _rorx_u32 (x06 + x05, 32 - 9);				 \
		x08 ^= _rorx_u32 (x11 + x10, 32 - 9);	x13 ^= _rorx_u32 (x12 + x15, 32 - 9);				 \
		x03 ^= _rorx_u32 (x02 + x01, 32 - 13);	x04 ^= _rorx_u32 (x07 + x06, 32 - 13);				 \
		x09 ^= _rorx_u32 (x08 + x11, 32 - 13);	x14 ^= _rorx_u32 (x13 + x12, 32 - 13);				 \
		x00 ^= _rorx_u32 (x03 + x02, 32 - 18);	x05 ^= _rorx_u32 (x04 + x07, 32 - 18);				 \
		x10 ^= _rorx_u32 (x09 + x08, 32 - 18);	x15 ^= _rorx_u32 (x14 + x13, 32 - 18);				 \
	}

	SALSA_STEP;
	SALSA_STEP;
	SALSA_STEP;
	SALSA_STEP;

#undef x00
#undef x01
#undef x02
#undef x03
#undef x04
#undef x05
#undef x06
#undef x07

#undef x08
#undef x09
#undef x10
#undef x11
#undef x12
#undef x13
#undef x14
#undef x15

#undef SALSA_STEP

	output0 = _mm256_add_epi32 (output0, x0);
	output1 = _mm256_add_epi32 (output1, x1);
}

static void xor_salsa8_parallel8 (__m256i input[2 * 8], __m256i output[2 * 8]) {
	//8x input[0] -> x00..08 (xorX[thread*2 + 0]), input[1] -> x09..x15 (xorX[thread*2 + 1])
	__m256i xorX[16] = {
		//thread 0
		output[0] = _mm256_xor_si256 (output[0], input[0]),
		output[1] = _mm256_xor_si256 (output[1], input[1]),
		//thread 1
		output[2] = _mm256_xor_si256 (output[2], input[2]),
		output[3] = _mm256_xor_si256 (output[3], input[3]),
		//thread 2
		output[4] = _mm256_xor_si256 (output[4], input[4]),
		output[5] = _mm256_xor_si256 (output[5], input[5]),
		//thread 3
		output[6] = _mm256_xor_si256 (output[6], input[6]),
		output[7] = _mm256_xor_si256 (output[7], input[7]),
		//thread 4
		output[8] = _mm256_xor_si256 (output[8], input[8]),
		output[9] = _mm256_xor_si256 (output[9], input[9]),
		//thread 5
		output[10] = _mm256_xor_si256 (output[10], input[10]),
		output[11] = _mm256_xor_si256 (output[11], input[11]),
		//thread 6
		output[12] = _mm256_xor_si256 (output[12], input[12]),
		output[13] = _mm256_xor_si256 (output[13], input[13]),
		//thread 7
		output[14] = _mm256_xor_si256 (output[14], input[14]),
		output[15] = _mm256_xor_si256 (output[15], input[15]),
	};

	//Transpose matrix
	__m256i calcX[16] = {
		_mm256_setr_epi32 (xorX[0].m256i_u32[0], xorX[2].m256i_u32[0], xorX[4].m256i_u32[0], xorX[6].m256i_u32[0], xorX[8].m256i_u32[0], xorX[10].m256i_u32[0], xorX[12].m256i_u32[0], xorX[14].m256i_u32[0]),
		_mm256_setr_epi32 (xorX[0].m256i_u32[1], xorX[2].m256i_u32[1], xorX[4].m256i_u32[1], xorX[6].m256i_u32[1], xorX[8].m256i_u32[1], xorX[10].m256i_u32[1], xorX[12].m256i_u32[1], xorX[14].m256i_u32[1]),
		_mm256_setr_epi32 (xorX[0].m256i_u32[2], xorX[2].m256i_u32[2], xorX[4].m256i_u32[2], xorX[6].m256i_u32[2], xorX[8].m256i_u32[2], xorX[10].m256i_u32[2], xorX[12].m256i_u32[2], xorX[14].m256i_u32[2]),
		_mm256_setr_epi32 (xorX[0].m256i_u32[3], xorX[2].m256i_u32[3], xorX[4].m256i_u32[3], xorX[6].m256i_u32[3], xorX[8].m256i_u32[3], xorX[10].m256i_u32[3], xorX[12].m256i_u32[3], xorX[14].m256i_u32[3]),
		_mm256_setr_epi32 (xorX[0].m256i_u32[4], xorX[2].m256i_u32[4], xorX[4].m256i_u32[4], xorX[6].m256i_u32[4], xorX[8].m256i_u32[4], xorX[10].m256i_u32[4], xorX[12].m256i_u32[4], xorX[14].m256i_u32[4]),
		_mm256_setr_epi32 (xorX[0].m256i_u32[5], xorX[2].m256i_u32[5], xorX[4].m256i_u32[5], xorX[6].m256i_u32[5], xorX[8].m256i_u32[5], xorX[10].m256i_u32[5], xorX[12].m256i_u32[5], xorX[14].m256i_u32[5]),
		_mm256_setr_epi32 (xorX[0].m256i_u32[6], xorX[2].m256i_u32[6], xorX[4].m256i_u32[6], xorX[6].m256i_u32[6], xorX[8].m256i_u32[6], xorX[10].m256i_u32[6], xorX[12].m256i_u32[6], xorX[14].m256i_u32[6]),
		_mm256_setr_epi32 (xorX[0].m256i_u32[7], xorX[2].m256i_u32[7], xorX[4].m256i_u32[7], xorX[6].m256i_u32[7], xorX[8].m256i_u32[7], xorX[10].m256i_u32[7], xorX[12].m256i_u32[7], xorX[14].m256i_u32[7]),

		_mm256_setr_epi32 (xorX[1].m256i_u32[0], xorX[3].m256i_u32[0], xorX[5].m256i_u32[0], xorX[7].m256i_u32[0], xorX[9].m256i_u32[0], xorX[11].m256i_u32[0], xorX[13].m256i_u32[0], xorX[15].m256i_u32[0]),
		_mm256_setr_epi32 (xorX[1].m256i_u32[1], xorX[3].m256i_u32[1], xorX[5].m256i_u32[1], xorX[7].m256i_u32[1], xorX[9].m256i_u32[1], xorX[11].m256i_u32[1], xorX[13].m256i_u32[1], xorX[15].m256i_u32[1]),
		_mm256_setr_epi32 (xorX[1].m256i_u32[2], xorX[3].m256i_u32[2], xorX[5].m256i_u32[2], xorX[7].m256i_u32[2], xorX[9].m256i_u32[2], xorX[11].m256i_u32[2], xorX[13].m256i_u32[2], xorX[15].m256i_u32[2]),
		_mm256_setr_epi32 (xorX[1].m256i_u32[3], xorX[3].m256i_u32[3], xorX[5].m256i_u32[3], xorX[7].m256i_u32[3], xorX[9].m256i_u32[3], xorX[11].m256i_u32[3], xorX[13].m256i_u32[3], xorX[15].m256i_u32[3]),
		_mm256_setr_epi32 (xorX[1].m256i_u32[4], xorX[3].m256i_u32[4], xorX[5].m256i_u32[4], xorX[7].m256i_u32[4], xorX[9].m256i_u32[4], xorX[11].m256i_u32[4], xorX[13].m256i_u32[4], xorX[15].m256i_u32[4]),
		_mm256_setr_epi32 (xorX[1].m256i_u32[5], xorX[3].m256i_u32[5], xorX[5].m256i_u32[5], xorX[7].m256i_u32[5], xorX[9].m256i_u32[5], xorX[11].m256i_u32[5], xorX[13].m256i_u32[5], xorX[15].m256i_u32[5]),
		_mm256_setr_epi32 (xorX[1].m256i_u32[6], xorX[3].m256i_u32[6], xorX[5].m256i_u32[6], xorX[7].m256i_u32[6], xorX[9].m256i_u32[6], xorX[11].m256i_u32[6], xorX[13].m256i_u32[6], xorX[15].m256i_u32[6]),
		_mm256_setr_epi32 (xorX[1].m256i_u32[7], xorX[3].m256i_u32[7], xorX[5].m256i_u32[7], xorX[7].m256i_u32[7], xorX[9].m256i_u32[7], xorX[11].m256i_u32[7], xorX[13].m256i_u32[7], xorX[15].m256i_u32[7]),
	};

//#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define R(res, add1, add2, shift)																	 \
		calcX[res] = _mm256_xor_si256 (																 \
			calcX[res],																				 \
			_mm256_or_si256 (																		 \
				_mm256_slli_epi32 (_mm256_add_epi32 (calcX[add1], calcX[add2]), shift),				 \
				_mm256_srli_epi32 (_mm256_add_epi32 (calcX[add1], calcX[add2]), 32 - shift)			 \
			)																						 \
		)

#define SALSA_STEP	{																				\
		R (4, 0, 12, 7);	R (9, 5, 1, 7);															\
		R (14, 10, 6, 7);	R (3, 15, 11, 7);														\
		R (8, 4, 0, 9);		R (13, 9, 5, 9);														\
		R (2, 14, 10, 9);	R (7, 3, 15, 9);														\
		R (12, 8, 4, 13);	R (1, 13, 9, 13);														\
		R (6, 2, 14, 13);	R (11, 7, 3, 13);														\
		R (0, 12, 8, 18);	R (5, 1, 13, 18);														\
		R (10, 6, 2, 18);	R (15, 11, 7, 18);														\
																									\
		R (1, 0, 3, 7);		R (6, 5, 4, 7);															\
		R (11, 10, 9, 7);	R (12, 15, 14, 7);														\
		R (2, 1, 0, 9);		R (7, 6, 5, 9);															\
		R (8, 11, 10, 9);	R (13, 12, 15, 9);														\
		R (3, 2, 1, 13);	R (4, 7, 6, 13);														\
		R (9, 8, 11, 13);	R (14, 13, 12, 13);														\
		R (0, 3, 2, 18);	R (5, 4, 7, 18);														\
		R (10, 9, 8, 18);	R (15, 14, 13, 18);														\
	}

	SALSA_STEP;
	SALSA_STEP;
	SALSA_STEP;
	SALSA_STEP;

#undef SALSA_STEP
#undef R

	//Transpose back
	__m256i xX[16] = {
		//Thread 0
		_mm256_setr_epi32 (calcX[0].m256i_u32[0], calcX[1].m256i_u32[0], calcX[ 2].m256i_u32[0], calcX[ 3].m256i_u32[0], calcX[ 4].m256i_u32[0], calcX[ 5].m256i_u32[0], calcX[ 6].m256i_u32[0], calcX[ 7].m256i_u32[0]),
		_mm256_setr_epi32 (calcX[8].m256i_u32[0], calcX[9].m256i_u32[0], calcX[10].m256i_u32[0], calcX[11].m256i_u32[0], calcX[12].m256i_u32[0], calcX[13].m256i_u32[0], calcX[14].m256i_u32[0], calcX[15].m256i_u32[0]),
		//Thread 1
		_mm256_setr_epi32 (calcX[0].m256i_u32[1], calcX[1].m256i_u32[1], calcX[ 2].m256i_u32[1], calcX[ 3].m256i_u32[1], calcX[ 4].m256i_u32[1], calcX[ 5].m256i_u32[1], calcX[ 6].m256i_u32[1], calcX[ 7].m256i_u32[1]),
		_mm256_setr_epi32 (calcX[8].m256i_u32[1], calcX[9].m256i_u32[1], calcX[10].m256i_u32[1], calcX[11].m256i_u32[1], calcX[12].m256i_u32[1], calcX[13].m256i_u32[1], calcX[14].m256i_u32[1], calcX[15].m256i_u32[1]),
		//Thread 2
		_mm256_setr_epi32 (calcX[0].m256i_u32[2], calcX[1].m256i_u32[2], calcX[ 2].m256i_u32[2], calcX[ 3].m256i_u32[2], calcX[ 4].m256i_u32[2], calcX[ 5].m256i_u32[2], calcX[ 6].m256i_u32[2], calcX[ 7].m256i_u32[2]),
		_mm256_setr_epi32 (calcX[8].m256i_u32[2], calcX[9].m256i_u32[2], calcX[10].m256i_u32[2], calcX[11].m256i_u32[2], calcX[12].m256i_u32[2], calcX[13].m256i_u32[2], calcX[14].m256i_u32[2], calcX[15].m256i_u32[2]),
		//Thread 3
		_mm256_setr_epi32 (calcX[0].m256i_u32[3], calcX[1].m256i_u32[3], calcX[ 2].m256i_u32[3], calcX[ 3].m256i_u32[3], calcX[ 4].m256i_u32[3], calcX[ 5].m256i_u32[3], calcX[ 6].m256i_u32[3], calcX[ 7].m256i_u32[3]),
		_mm256_setr_epi32 (calcX[8].m256i_u32[3], calcX[9].m256i_u32[3], calcX[10].m256i_u32[3], calcX[11].m256i_u32[3], calcX[12].m256i_u32[3], calcX[13].m256i_u32[3], calcX[14].m256i_u32[3], calcX[15].m256i_u32[3]),
		//Thread 4
		_mm256_setr_epi32 (calcX[0].m256i_u32[4], calcX[1].m256i_u32[4], calcX[ 2].m256i_u32[4], calcX[ 3].m256i_u32[4], calcX[ 4].m256i_u32[4], calcX[ 5].m256i_u32[4], calcX[ 6].m256i_u32[4], calcX[ 7].m256i_u32[4]),
		_mm256_setr_epi32 (calcX[8].m256i_u32[4], calcX[9].m256i_u32[4], calcX[10].m256i_u32[4], calcX[11].m256i_u32[4], calcX[12].m256i_u32[4], calcX[13].m256i_u32[4], calcX[14].m256i_u32[4], calcX[15].m256i_u32[4]),
		//Thread 5
		_mm256_setr_epi32 (calcX[0].m256i_u32[5], calcX[1].m256i_u32[5], calcX[ 2].m256i_u32[5], calcX[ 3].m256i_u32[5], calcX[ 4].m256i_u32[5], calcX[ 5].m256i_u32[5], calcX[ 6].m256i_u32[5], calcX[ 7].m256i_u32[5]),
		_mm256_setr_epi32 (calcX[8].m256i_u32[5], calcX[9].m256i_u32[5], calcX[10].m256i_u32[5], calcX[11].m256i_u32[5], calcX[12].m256i_u32[5], calcX[13].m256i_u32[5], calcX[14].m256i_u32[5], calcX[15].m256i_u32[5]),
		//Thread 6
		_mm256_setr_epi32 (calcX[0].m256i_u32[6], calcX[1].m256i_u32[6], calcX[ 2].m256i_u32[6], calcX[ 3].m256i_u32[6], calcX[ 4].m256i_u32[6], calcX[ 5].m256i_u32[6], calcX[ 6].m256i_u32[6], calcX[ 7].m256i_u32[6]),
		_mm256_setr_epi32 (calcX[8].m256i_u32[6], calcX[9].m256i_u32[6], calcX[10].m256i_u32[6], calcX[11].m256i_u32[6], calcX[12].m256i_u32[6], calcX[13].m256i_u32[6], calcX[14].m256i_u32[6], calcX[15].m256i_u32[6]),
		//Thread 7
		_mm256_setr_epi32 (calcX[0].m256i_u32[7], calcX[1].m256i_u32[7], calcX[ 2].m256i_u32[7], calcX[ 3].m256i_u32[7], calcX[ 4].m256i_u32[7], calcX[ 5].m256i_u32[7], calcX[ 6].m256i_u32[7], calcX[ 7].m256i_u32[7]),
		_mm256_setr_epi32 (calcX[8].m256i_u32[7], calcX[9].m256i_u32[7], calcX[10].m256i_u32[7], calcX[11].m256i_u32[7], calcX[12].m256i_u32[7], calcX[13].m256i_u32[7], calcX[14].m256i_u32[7], calcX[15].m256i_u32[7]),
	};

	//Add result
	output[0]  = _mm256_add_epi32 (output[0],  xX[0]);
	output[1]  = _mm256_add_epi32 (output[1],  xX[1]);
	output[2]  = _mm256_add_epi32 (output[2],  xX[2]);
	output[3]  = _mm256_add_epi32 (output[3],  xX[3]);
	output[4]  = _mm256_add_epi32 (output[4],  xX[4]);
	output[5]  = _mm256_add_epi32 (output[5],  xX[5]);
	output[6]  = _mm256_add_epi32 (output[6],  xX[6]);
	output[7]  = _mm256_add_epi32 (output[7],  xX[7]);
	output[8]  = _mm256_add_epi32 (output[8],  xX[8]);
	output[9]  = _mm256_add_epi32 (output[9],  xX[9]);
	output[10] = _mm256_add_epi32 (output[10], xX[10]);
	output[11] = _mm256_add_epi32 (output[11], xX[11]);
	output[12] = _mm256_add_epi32 (output[12], xX[12]);
	output[13] = _mm256_add_epi32 (output[13], xX[13]);
	output[14] = _mm256_add_epi32 (output[14], xX[14]);
	output[15] = _mm256_add_epi32 (output[15], xX[15]);
}

static void scrypt_core (uint32_t* X) {
	const int32_t N = 1024;
	ALIGN_PREFIX (32) uint32_t V[N * 32 * SCRYPT_STEP_COUNT] ALIGN_POSTFIX (32);

//#define TEST_CORE1_PAR8_IN												   \
//	__m256i ti1 = srcX[2], ti2 = srcX[3], to1 = srcX[0], to2 = srcX[1];
//
//#define TEST_CORE1_PAR8													   \
//	__m256i ti[16], to[16];												   \
//	for (int ii = 0; ii < 8; ++ii) {									   \
//		ti[ii * 2 + 0] = ti1;	to[ii * 2 + 0] = to1;					   \
//		ti[ii * 2 + 1] = ti2;	to[ii * 2 + 1] = to2;					   \
//	}																	   \
//	xor_salsa8_parallel8 (ti, to);


#define CORE1_STEP(step, i) 												 \
		srcX = (__m256i*) &X[step * 32];									 \
		destV = (__m256i*) &V[step * N * 32 + i * 32];						 \
																			 \
		_mm256_store_si256 (destV++, srcX[0]);								 \
		_mm256_store_si256 (destV++, srcX[1]);								 \
		_mm256_store_si256 (destV++, srcX[2]);								 \
		_mm256_store_si256 (destV, srcX[3]);								 \
																			 \
		xor_salsa8 (srcX[2], srcX[3], srcX[0], srcX[1]);					 \
		xor_salsa8 (srcX[0], srcX[1], srcX[2], srcX[3]);

#define CORE2_STEP(step)													 \
		j = 32 * (X[step * 32 + 16] & (N - 1));								 \
																			 \
		srcV = (__m256i*) &V[step * N * 32 + j];							 \
		destX = (__m256i*) &X[step * 32 + 0];								 \
		destX[0] = _mm256_xor_si256 (destX[0], *srcV++);					 \
		destX[1] = _mm256_xor_si256 (destX[1], *srcV++);					 \
		destX[2] = _mm256_xor_si256 (destX[2], *srcV++);					 \
		destX[3] = _mm256_xor_si256 (destX[3], *srcV);						 \
																			 \
		xor_salsa8 (destX[2], destX[3], destX[0], destX[1]);				 \
		xor_salsa8 (destX[0], destX[1], destX[2], destX[3]);

	for (uint32_t i = 0; i < N; i++) {
		//memcpy (&V[i * 32], X, 128);
		//xor_salsa8 (&X[0], &X[16]);
		//xor_salsa8 (&X[16], &X[0]);

		__m256i *srcX, *destV;

		CORE1_STEP(0, i);
		//CORE1_STEP(1, i);
		//CORE1_STEP(2, i);
		//CORE1_STEP(3, i);
	}

	for (uint32_t i = 0; i < N; i++) {
		//uint32_t j = 32 * (X[16] & (N - 1));
		//for (uint32_t k = 0; k < 32; k++) {
		//	X[k] ^= V[j + k];
		//}
		//xor_salsa8 (&X[0], &X[16]);
		//xor_salsa8 (&X[16], &X[0]);

		uint32_t j;
		__m256i *srcV, *destX;

		CORE2_STEP(0);
		//CORE2_STEP(1);
		//CORE2_STEP(2);
		//CORE2_STEP(3);
	}

#undef CORE1_STEP
#undef CORE2_STEP
}

static void scrypt_1024_1_1_256 (uint32_t stepCount, const uint32_t *input, uint32_t *output, uint32_t *midstate) {
	uint32_t tstate[8 * SCRYPT_STEP_COUNT], ostate[8 * SCRYPT_STEP_COUNT];
	ALIGN_PREFIX (32) uint32_t X[32 * SCRYPT_STEP_COUNT] ALIGN_POSTFIX (32);

#define INIT_SCRYPT(step) {																				\
		const size_t eightPos = step * 8;																\
		const size_t twentyPos = step * 20;																\
		memcpy (&tstate[eightPos], &midstate[eightPos], 32);											\
		HMAC_SHA256_80_init (&input[twentyPos], &tstate[eightPos], &ostate[eightPos]);					\
		PBKDF2_SHA256_80_128 (&tstate[eightPos], &ostate[eightPos], &input[twentyPos], &X[step * 32]);	\
	}

	switch (stepCount) {
	case 4:
		INIT_SCRYPT (3);
	case 3:
		INIT_SCRYPT (2);
	case 2:
		INIT_SCRYPT (1);
	case 1:
		INIT_SCRYPT (0);
		break;
	default:
		assert (0);
	}

	scrypt_core (X);

#define RELEASE_SCRYPT(step) {																			\
		const size_t eightPos = step * 8;																\
		PBKDF2_SHA256_128_32 (&tstate[eightPos], &ostate[eightPos], &X[step * 32], &output[eightPos]);	\
	}

	switch (stepCount) {
	case 4:
		RELEASE_SCRYPT (3);
	case 3:
		RELEASE_SCRYPT (2);
	case 2:
		RELEASE_SCRYPT (1);
	case 1:
		RELEASE_SCRYPT (0);
		break;
	default:
		assert (0);
	}

#undef INIT_SCRYPT
#undef RELEASE_SCRYPT
}

//Speedup cypher caller

#define SCRYPT_ITERATION_COUNT 1024

uint32_t initSpeedupCypher () {
	return SCRYPT_STEP_COUNT; //Step count
}

void releaseSpeedupCypher () {
}

void speedupCypher (uint32_t stepCount, const uint32_t* input, uint32_t* output, size_t sourceIntegerCount, size_t targetIntegerCount) {
	uint32_t midstate[8 * SCRYPT_STEP_COUNT] = { 1, 2, 3, 4, 5, 6, 7, 8,
		/*1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8*/ }; //test values

	scrypt_1024_1_1_256 (stepCount, input, output, midstate);

	////TEST
	//FILE* fout = fopen ("d:\\work\\salsa2\\new.dat", "ab"); //"wb" to delete content
	//if (fout) {
	//	for (int i = 0; i < targetIntegerCount; ++i) {
	//		fprintf (fout, "0x%08x\n", output[i]);
	//	}
	//	fclose (fout);
	//}
	////END TEST
}
