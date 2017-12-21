#define _CRT_SECURE_NO_WARNINGS

#include <stdint.h>
#include <intrin.h>
#include <cstring>
#include <cassert>
#include <cstdio>

#define ALIGN_PREFIX(x) __declspec(align(x))

#define SCRYPT_STEP_COUNT 8

static inline uint32_t swab32 (uint32_t v) {
	return _byteswap_ulong (v);
}

extern "C" {
	void sha256_init (uint32_t *state);
	void sha256_transform (uint32_t *state, const uint32_t *block, int swap);

	void sha256_init_avx (uint32_t *state);
	void sha256_transform_avx (uint32_t *state, const uint32_t *block, int swap);
}

//static const uint32_t keypad[12] = {
//	0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000280
//};
//static const uint32_t innerpad[11] = {
//	0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x000004a0
//};
//static const uint32_t outerpad[8] = {
//	0x80000000, 0, 0, 0, 0, 0, 0, 0x00000300
//};
static const uint32_t finalblk[16] = {
	0x00000001, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000620
};

static inline void HMAC_SHA256_80_init (const uint32_t *key, uint32_t *tstate, uint32_t *ostate) {
	ALIGN_PREFIX (32) uint32_t pad[16] = {
		key[16], key[17], key[18], key[19],
		0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000280 //keypad
	};

	/* tstate is assumed to contain the midstate of key */
	sha256_transform (tstate, pad, 0);
	
	const __m256i ihash = _mm256_loadu_si256 ((const __m256i*) tstate);

	sha256_init (ostate);
	((__m256i*)pad)[0] = _mm256_xor_si256 (ihash, _mm256_set1_epi32 (0x5c5c5c5c));
	((__m256i*)pad)[1] = _mm256_set1_epi32 (0x5c5c5c5c);
	sha256_transform (ostate, pad, 0);

	sha256_init (tstate);
	((__m256i*)pad)[0] = _mm256_xor_si256 (ihash, _mm256_set1_epi32 (0x36363636));
	((__m256i*)pad)[1] = _mm256_set1_epi32 (0x36363636);
	sha256_transform (tstate, pad, 0);
}

static void PBKDF2_SHA256_80_128 (const uint32_t *tstate, const uint32_t *ostate, const uint32_t *salt, uint32_t *output) {
	ALIGN_PREFIX (32) uint32_t istate[8];
	ALIGN_PREFIX (32) uint32_t ostate2[8];
	ALIGN_PREFIX (32) uint32_t ibuf[16] = {
		0, 0, 0, 0, 0,
		0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x000004a0 //innerpad
	};
	ALIGN_PREFIX (32) uint32_t obuf[16] = {
		0, 0, 0, 0, 0, 0, 0, 0,
		0x80000000, 0, 0, 0, 0, 0, 0, 0x00000300 //outerpad
	};

	*(__m256i*)istate = _mm256_loadu_si256 ((const __m256i*) tstate);
	sha256_transform (istate, salt, 0);

	*(__m128i*) &ibuf[0] = _mm_loadu_si128 ((const __m128i*) &salt[16]);

	__m256i swab = _mm256_setr_epi8 (
		0x03, 0x02, 0x01, 0x00,
		0x07, 0x06, 0x05, 0x04,
		0x0b, 0x0a, 0x09, 0x08,
		0x0f, 0x0e, 0x0d, 0x0c,

		0x03, 0x02, 0x01, 0x00,
		0x07, 0x06, 0x05, 0x04,
		0x0b, 0x0a, 0x09, 0x08,
		0x0f, 0x0e, 0x0d, 0x0c
	);

	//Step 1
	*(__m256i*)obuf = _mm256_load_si256 ((const __m256i*) istate);

	ibuf[4] = 1;
	sha256_transform (obuf, ibuf, 0);

	*(__m256i*)ostate2 = _mm256_loadu_si256 ((const __m256i*) ostate);
	sha256_transform (ostate2, obuf, 0);

	((__m256i*)output)[0] = _mm256_shuffle_epi8 (*(__m256i*)ostate2, swab);

	//Step 2
	*(__m256i*)obuf = _mm256_load_si256 ((const __m256i*) istate);

	ibuf[4] = 2;
	sha256_transform (obuf, ibuf, 0);

	*(__m256i*)ostate2 = _mm256_loadu_si256 ((const __m256i*) ostate);
	sha256_transform (ostate2, obuf, 0);

	((__m256i*)output)[1] = _mm256_shuffle_epi8 (*(__m256i*)ostate2, swab);

	//Step 3
	*(__m256i*)obuf = _mm256_load_si256 ((const __m256i*) istate);

	ibuf[4] = 3;
	sha256_transform (obuf, ibuf, 0);

	*(__m256i*)ostate2 = _mm256_loadu_si256 ((const __m256i*) ostate);
	sha256_transform (ostate2, obuf, 0);

	((__m256i*)output)[2] = _mm256_shuffle_epi8 (*(__m256i*)ostate2, swab);

	//Step 4
	*(__m256i*)obuf = _mm256_load_si256 ((const __m256i*) istate);

	ibuf[4] = 4;
	sha256_transform (obuf, ibuf, 0);

	*(__m256i*)ostate2 = _mm256_loadu_si256 ((const __m256i*) ostate);
	sha256_transform (ostate2, obuf, 0);

	((__m256i*)output)[3] = _mm256_shuffle_epi8 (*(__m256i*)ostate2, swab);
}

static void PBKDF2_SHA256_128_32 (uint32_t *tstate, uint32_t *ostate, const uint32_t *salt, uint32_t *output) {
	sha256_transform (tstate, salt, 1);
	sha256_transform (tstate, salt + 16, 1);
	sha256_transform (tstate, finalblk, 0);

	ALIGN_PREFIX (32) uint32_t buf[16] = {
		tstate[0], tstate[1], tstate[2], tstate[3], tstate[4], tstate[5], tstate[6], tstate[7],
		0x80000000, 0, 0, 0, 0, 0, 0, 0x00000300 //outerpad
	};

	sha256_transform (ostate, buf, 0);
	
	__m256i swab = _mm256_setr_epi8 (
		0x03, 0x02, 0x01, 0x00,
		0x07, 0x06, 0x05, 0x04,
		0x0b, 0x0a, 0x09, 0x08,
		0x0f, 0x0e, 0x0d, 0x0c,

		0x03, 0x02, 0x01, 0x00,
		0x07, 0x06, 0x05, 0x04,
		0x0b, 0x0a, 0x09, 0x08,
		0x0f, 0x0e, 0x0d, 0x0c
	);

	_mm256_storeu_si256 ((__m256i*) output, _mm256_shuffle_epi8 (*(__m256i*)ostate, swab));
}

ALIGN_PREFIX (32) static uint32_t speedupSalsaCalcXBuffer[16 * 8];

static void xor_salsa8_parallel8 (__m256i input[2 * 8], __m256i output[2 * 8], uint32_t threadLen) {
	//8x input[0] -> x00..08 (xorX[thread*2 + 0]), input[1] -> x09..x15 (xorX[thread*2 + 1])
	//__m256i xorX[16] = {
		//thread 0
		output[0*threadLen + 0] = _mm256_xor_si256 (output[0*threadLen + 0], input[0*threadLen + 0]);
		output[0*threadLen + 1] = _mm256_xor_si256 (output[0*threadLen + 1], input[0*threadLen + 1]);
		//thread 1
		output[1*threadLen + 0] = _mm256_xor_si256 (output[1*threadLen + 0], input[1*threadLen + 0]);
		output[1*threadLen + 1] = _mm256_xor_si256 (output[1*threadLen + 1], input[1*threadLen + 1]);
		//thread 2
		output[2*threadLen + 0] = _mm256_xor_si256 (output[2*threadLen + 0], input[2*threadLen + 0]);
		output[2*threadLen + 1] = _mm256_xor_si256 (output[2*threadLen + 1], input[2*threadLen + 1]);
		//thread 3
		output[3*threadLen + 0] = _mm256_xor_si256 (output[3*threadLen + 0], input[3*threadLen + 0]);
		output[3*threadLen + 1] = _mm256_xor_si256 (output[3*threadLen + 1], input[3*threadLen + 1]);
		//thread 4
		output[4*threadLen + 0] = _mm256_xor_si256 (output[4*threadLen + 0], input[4*threadLen + 0]);
		output[4*threadLen + 1] = _mm256_xor_si256 (output[4*threadLen + 1], input[4*threadLen + 1]);
		//thread 5
		output[5*threadLen + 0] = _mm256_xor_si256 (output[5*threadLen + 0], input[5*threadLen + 0]);
		output[5*threadLen + 1] = _mm256_xor_si256 (output[5*threadLen + 1], input[5*threadLen + 1]);
		//thread 6
		output[6*threadLen + 0] = _mm256_xor_si256 (output[6*threadLen + 0], input[6*threadLen + 0]);
		output[6*threadLen + 1] = _mm256_xor_si256 (output[6*threadLen + 1], input[6*threadLen + 1]);
		//thread 7
		output[7*threadLen + 0] = _mm256_xor_si256 (output[7*threadLen + 0], input[7*threadLen + 0]);
		output[7*threadLen + 1] = _mm256_xor_si256 (output[7*threadLen + 1], input[7*threadLen + 1]);
	//};

	//Transpose matrix (calcX[i] = xorX[0].m256i_u32[i] <= i=0..7, calcX[i] = xorX[1].m256i_u32[i-8] <= i=8..15)
	const __m256i vindex = _mm256_setr_epi32 (0, threadLen * 8, 2 * threadLen * 8, 3 * threadLen * 8, 4 * threadLen * 8, 5 * threadLen * 8, 6 * threadLen * 8, 7 * threadLen * 8);
	const int* xBase = (const int*) output;

	__m256i* calcX = (__m256i*) speedupSalsaCalcXBuffer;
	calcX[0] = _mm256_i32gather_epi32 (xBase, vindex, 4);
	calcX[1] = _mm256_i32gather_epi32 (xBase + 1, vindex, 4);
	calcX[2] = _mm256_i32gather_epi32 (xBase + 2, vindex, 4);
	calcX[3] = _mm256_i32gather_epi32 (xBase + 3, vindex, 4);
	calcX[4] = _mm256_i32gather_epi32 (xBase + 4, vindex, 4);
	calcX[5] = _mm256_i32gather_epi32 (xBase + 5, vindex, 4);
	calcX[6] = _mm256_i32gather_epi32 (xBase + 6, vindex, 4);
	calcX[7] = _mm256_i32gather_epi32 (xBase + 7, vindex, 4);

	calcX[8] = _mm256_i32gather_epi32 (xBase + 8, vindex, 4);
	calcX[9] = _mm256_i32gather_epi32 (xBase + 9, vindex, 4);
	calcX[10] = _mm256_i32gather_epi32 (xBase + 10, vindex, 4);
	calcX[11] = _mm256_i32gather_epi32 (xBase + 11, vindex, 4);
	calcX[12] = _mm256_i32gather_epi32 (xBase + 12, vindex, 4);
	calcX[13] = _mm256_i32gather_epi32 (xBase + 13, vindex, 4);
	calcX[14] = _mm256_i32gather_epi32 (xBase + 14, vindex, 4);
	calcX[15] = _mm256_i32gather_epi32 (xBase + 15, vindex, 4);

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

	//Transpose back (extract thread results -> xX[i] = calcX[0..8].m256i_u32[i])
	const __m256i vindex2 = _mm256_setr_epi32 (0, 8, 16, 24, 32, 40, 48, 56);
	const int* calcXBase = (const int*) speedupSalsaCalcXBuffer;
	//__m256i jVal = _mm256_i32gather_epi32 (calcXBase, vindex2, 4);

	__m256i xX[16] = {
		//Thread 0
		_mm256_i32gather_epi32 (calcXBase + 0 * 8 + 0, vindex2, 4),
		_mm256_i32gather_epi32 (calcXBase + 8 * 8 + 0, vindex2, 4),
		//Thread 1
		_mm256_i32gather_epi32 (calcXBase + 0 * 8 + 1, vindex2, 4),
		_mm256_i32gather_epi32 (calcXBase + 8 * 8 + 1, vindex2, 4),
		//Thread 2
		_mm256_i32gather_epi32 (calcXBase + 0 * 8 + 2, vindex2, 4),
		_mm256_i32gather_epi32 (calcXBase + 8 * 8 + 2, vindex2, 4),
		//Thread 3
		_mm256_i32gather_epi32 (calcXBase + 0 * 8 + 3, vindex2, 4),
		_mm256_i32gather_epi32 (calcXBase + 8 * 8 + 3, vindex2, 4),
		//Thread 4
		_mm256_i32gather_epi32 (calcXBase + 0 * 8 + 4, vindex2, 4),
		_mm256_i32gather_epi32 (calcXBase + 8 * 8 + 4, vindex2, 4),
		//Thread 5
		_mm256_i32gather_epi32 (calcXBase + 0 * 8 + 5, vindex2, 4),
		_mm256_i32gather_epi32 (calcXBase + 8 * 8 + 5, vindex2, 4),
		//Thread 6
		_mm256_i32gather_epi32 (calcXBase + 0 * 8 + 6, vindex2, 4),
		_mm256_i32gather_epi32 (calcXBase + 8 * 8 + 6, vindex2, 4),
		//Thread 7
		_mm256_i32gather_epi32 (calcXBase + 0 * 8 + 7, vindex2, 4),
		_mm256_i32gather_epi32 (calcXBase + 8 * 8 + 7, vindex2, 4)
	};

	//Calculate output
	//Thread 0
	output[0*threadLen + 0] = _mm256_add_epi32 (output[0*threadLen + 0], xX[0]);
	output[0*threadLen + 1] = _mm256_add_epi32 (output[0*threadLen + 1], xX[1]);
	//Thread 1
	output[1*threadLen + 0] = _mm256_add_epi32 (output[1*threadLen + 0], xX[2]);
	output[1*threadLen + 1] = _mm256_add_epi32 (output[1*threadLen + 1], xX[3]);
	//Thread 2
	output[2*threadLen + 0] = _mm256_add_epi32 (output[2*threadLen + 0], xX[4]);
	output[2*threadLen + 1] = _mm256_add_epi32 (output[2*threadLen + 1], xX[5]);
	//Thread 3
	output[3*threadLen + 0] = _mm256_add_epi32 (output[3*threadLen + 0], xX[6]);
	output[3*threadLen + 1] = _mm256_add_epi32 (output[3*threadLen + 1], xX[7]);
	//Thread 4
	output[4*threadLen + 0] = _mm256_add_epi32 (output[4*threadLen + 0], xX[8]);
	output[4*threadLen + 1] = _mm256_add_epi32 (output[4*threadLen + 1], xX[9]);
	//Thread 5
	output[5*threadLen + 0] = _mm256_add_epi32 (output[5*threadLen + 0], xX[10]);
	output[5*threadLen + 1] = _mm256_add_epi32 (output[5*threadLen + 1], xX[11]);
	//Thread 6
	output[6*threadLen + 0] = _mm256_add_epi32 (output[6*threadLen + 0], xX[12]);
	output[6*threadLen + 1] = _mm256_add_epi32 (output[6*threadLen + 1], xX[13]);
	//Thread 7
	output[7*threadLen + 0] = _mm256_add_epi32 (output[7*threadLen + 0], xX[14]);
	output[7*threadLen + 1] = _mm256_add_epi32 (output[7*threadLen + 1], xX[15]);
}

ALIGN_PREFIX (32) static uint32_t speedupScryptV[1024 * 32 * SCRYPT_STEP_COUNT];

static void scrypt_core (uint32_t* X) {
	const int32_t N = 1024;

#define CORE1_PRE_STEP(step, i) { 											 \
		__m256i* srcX = (__m256i*) &X[step * 32];							 \
		__m256i* destV = (__m256i*) &speedupScryptV[step * N * 32 + i * 32]; \
																			 \
		_mm256_store_si256 (destV++, srcX[0]);								 \
		_mm256_store_si256 (destV++, srcX[1]);								 \
		_mm256_store_si256 (destV++, srcX[2]);								 \
		_mm256_store_si256 (destV, srcX[3]);								 \
	}

#define CORE2_PRE_STEP(step) {												 \
		uint32_t j = 32 * (X[step * 32 + 16] & (N - 1));					 \
																			 \
		__m256i* srcV = (__m256i*) &speedupScryptV[step * N * 32 + j];		 \
		__m256i* destX = (__m256i*) &X[step * 32];							 \
		destX[0] = _mm256_xor_si256 (destX[0], *srcV++);					 \
		destX[1] = _mm256_xor_si256 (destX[1], *srcV++);					 \
		destX[2] = _mm256_xor_si256 (destX[2], *srcV++);					 \
		destX[3] = _mm256_xor_si256 (destX[3], *srcV);						 \
	}

	for (uint32_t i = 0; i < N; i++) {
		CORE1_PRE_STEP (0, i);
		CORE1_PRE_STEP (1, i);
		CORE1_PRE_STEP (2, i);
		CORE1_PRE_STEP (3, i);
		CORE1_PRE_STEP (4, i);
		CORE1_PRE_STEP (5, i);
		CORE1_PRE_STEP (6, i);
		CORE1_PRE_STEP (7, i);

		__m256i* srcX = (__m256i*) &X[0 * 32];
		xor_salsa8_parallel8 (&srcX[2], &srcX[0], 4);
		xor_salsa8_parallel8 (&srcX[0], &srcX[2], 4);
	}

	for (uint32_t i = 0; i < N; i++) {
		CORE2_PRE_STEP (0);
		CORE2_PRE_STEP (1);
		CORE2_PRE_STEP (2);
		CORE2_PRE_STEP (3);
		CORE2_PRE_STEP (4);
		CORE2_PRE_STEP (5);
		CORE2_PRE_STEP (6);
		CORE2_PRE_STEP (7);

		__m256i* destX = (__m256i*) &X[0 * 32];
		xor_salsa8_parallel8 (&destX[2], &destX[0], 4);
		xor_salsa8_parallel8 (&destX[0], &destX[2], 4);
	}

#undef CORE1_STEP
#undef CORE2_STEP
}

static void scrypt_1024_1_1_256 (uint32_t stepCount, const uint32_t *input, uint32_t *output, uint32_t *midstate) {
	ALIGN_PREFIX (32) uint32_t tstate[8 * SCRYPT_STEP_COUNT];
	ALIGN_PREFIX (32) uint32_t ostate[8 * SCRYPT_STEP_COUNT];
	ALIGN_PREFIX (32) uint32_t X[32 * SCRYPT_STEP_COUNT];

	memcpy (tstate, midstate, 32 * SCRYPT_STEP_COUNT);

	HMAC_SHA256_80_init (&input[0 * 20], &tstate[0 * 8], &ostate[0 * 8]);
	HMAC_SHA256_80_init (&input[1 * 20], &tstate[1 * 8], &ostate[1 * 8]);
	HMAC_SHA256_80_init (&input[2 * 20], &tstate[2 * 8], &ostate[2 * 8]);
	HMAC_SHA256_80_init (&input[3 * 20], &tstate[3 * 8], &ostate[3 * 8]);
	HMAC_SHA256_80_init (&input[4 * 20], &tstate[4 * 8], &ostate[4 * 8]);
	HMAC_SHA256_80_init (&input[5 * 20], &tstate[5 * 8], &ostate[5 * 8]);
	HMAC_SHA256_80_init (&input[6 * 20], &tstate[6 * 8], &ostate[6 * 8]);
	HMAC_SHA256_80_init (&input[7 * 20], &tstate[7 * 8], &ostate[7 * 8]);

	PBKDF2_SHA256_80_128 (&tstate[0 * 8], &ostate[0 * 8], &input[0 * 20], &X[0 * 32]);
	PBKDF2_SHA256_80_128 (&tstate[1 * 8], &ostate[1 * 8], &input[1 * 20], &X[1 * 32]);
	PBKDF2_SHA256_80_128 (&tstate[2 * 8], &ostate[2 * 8], &input[2 * 20], &X[2 * 32]);
	PBKDF2_SHA256_80_128 (&tstate[3 * 8], &ostate[3 * 8], &input[3 * 20], &X[3 * 32]);
	PBKDF2_SHA256_80_128 (&tstate[4 * 8], &ostate[4 * 8], &input[4 * 20], &X[4 * 32]);
	PBKDF2_SHA256_80_128 (&tstate[5 * 8], &ostate[5 * 8], &input[5 * 20], &X[5 * 32]);
	PBKDF2_SHA256_80_128 (&tstate[6 * 8], &ostate[6 * 8], &input[6 * 20], &X[6 * 32]);
	PBKDF2_SHA256_80_128 (&tstate[7 * 8], &ostate[7 * 8], &input[7 * 20], &X[7 * 32]);

	scrypt_core (X);

	PBKDF2_SHA256_128_32 (&tstate[0 * 8], &ostate[0 * 8], &X[0 * 32], &output[0 * 8]);
	PBKDF2_SHA256_128_32 (&tstate[1 * 8], &ostate[1 * 8], &X[1 * 32], &output[1 * 8]);
	PBKDF2_SHA256_128_32 (&tstate[2 * 8], &ostate[2 * 8], &X[2 * 32], &output[2 * 8]);
	PBKDF2_SHA256_128_32 (&tstate[3 * 8], &ostate[3 * 8], &X[3 * 32], &output[3 * 8]);
	PBKDF2_SHA256_128_32 (&tstate[4 * 8], &ostate[4 * 8], &X[4 * 32], &output[4 * 8]);
	PBKDF2_SHA256_128_32 (&tstate[5 * 8], &ostate[5 * 8], &X[5 * 32], &output[5 * 8]);
	PBKDF2_SHA256_128_32 (&tstate[6 * 8], &ostate[6 * 8], &X[6 * 32], &output[6 * 8]);
	PBKDF2_SHA256_128_32 (&tstate[7 * 8], &ostate[7 * 8], &X[7 * 32], &output[7 * 8]);
}

//Speedup cypher caller

uint32_t initSpeedupCypher () {
	return SCRYPT_STEP_COUNT; //Step count
}

void releaseSpeedupCypher () {
}

void speedupCypher (uint32_t stepCount, const uint32_t* input, uint32_t* output, size_t sourceIntegerCount, size_t targetIntegerCount) {
	uint32_t midstate[8 * SCRYPT_STEP_COUNT] = { 1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8 }; //test values

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
