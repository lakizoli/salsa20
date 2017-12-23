#define _CRT_SECURE_NO_WARNINGS

#include <stdint.h>
#include <intrin.h>

#define ALIGN_PREFIX(x) __declspec(align(x))

#define SCRYPT_THREAD_COUNT 8
//#define SCRYPT_USE_ASM

extern "C" {
	void sha256_transform_avx (__m256i state[1], const __m256i block[2], int swap);
}

#define sha256_init_avx()											\
	_mm256_setr_epi32 (												\
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,				\
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19				\
	)

static inline void HMAC_SHA256_80_init (const uint32_t *key, __m256i& tstate, __m256i& ostate) {
	__m256i pad[2] = {
		_mm256_setr_epi32 (
			key[16], key[17], key[18], key[19],
			0x80000000, 0, 0, 0 //keypad head
		), _mm256_setr_epi32 (
			0, 0, 0, 0, 0, 0, 0, 0x00000280 //keypad tail
		)
	};

	/* tstate is assumed to contain the midstate of key */
	sha256_transform_avx (&tstate, pad, 0);
	
	const __m256i ihash = tstate;

	ostate = sha256_init_avx ();
	pad[0] = _mm256_xor_si256 (ihash, _mm256_set1_epi32 (0x5c5c5c5c));
	pad[1] = _mm256_set1_epi32 (0x5c5c5c5c);
	sha256_transform_avx (&ostate, pad, 0);

	tstate = sha256_init_avx ();
	pad[0] = _mm256_xor_si256 (ihash, _mm256_set1_epi32 (0x36363636));
	pad[1] = _mm256_set1_epi32 (0x36363636);
	sha256_transform_avx (&tstate, pad, 0);
}

static void PBKDF2_SHA256_80_128 (const __m256i tstate, const __m256i ostate, const uint32_t *salt, __m256i output[4]) {
	__m256i ibuf[2] = {
		_mm256_setr_epi32 (
			0, 0, 0, 0, 0,
			0x80000000, 0, 0 //innerpad head
		), _mm256_setr_epi32 (
			0, 0, 0, 0, 0, 0, 0, 0x000004a0 //innerpad tail
		)
	};

	__m256i obuf[2] = {
		_mm256_setzero_si256 ()
		, _mm256_setr_epi32 (
			0x80000000, 0, 0, 0, 0, 0, 0, 0x00000300 //outerpad
		)
	};

	__m256i istate = tstate;
	sha256_transform_avx (&istate, (const __m256i*) salt, 0);

	*(__m128i*) &ibuf[0] = _mm_loadu_si128 ((const __m128i*) &salt[16]);

	const __m256i swab = _mm256_setr_epi8 (
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
	obuf[0] = istate;
	__m256i ostate2 = ostate;
	ibuf[0].m256i_u32[4] = 1;

	sha256_transform_avx (obuf, ibuf, 0);
	sha256_transform_avx (&ostate2, obuf, 0);
	output[0] = _mm256_shuffle_epi8 (ostate2, swab);

	//Step 2
	obuf[0] = istate;
	ostate2 = ostate;
	ibuf[0].m256i_u32[4] = 2;

	sha256_transform_avx (obuf, ibuf, 0);
	sha256_transform_avx (&ostate2, obuf, 0);
	output[1] = _mm256_shuffle_epi8 (ostate2, swab);

	//Step 3
	obuf[0] = istate;
	ostate2 = ostate;
	ibuf[0].m256i_u32[4] = 3;

	sha256_transform_avx (obuf, ibuf, 0);
	sha256_transform_avx (&ostate2, obuf, 0);
	output[2] = _mm256_shuffle_epi8 (ostate2, swab);

	//Step 4
	obuf[0] = istate;
	ostate2 = ostate;
	ibuf[0].m256i_u32[4] = 4;

	sha256_transform_avx (obuf, ibuf, 0);
	sha256_transform_avx (&ostate2, obuf, 0);
	output[3] = _mm256_shuffle_epi8 (ostate2, swab);
}

static void PBKDF2_SHA256_128_32 (__m256i& tstate, __m256i& ostate, const __m256i salt[4], uint32_t *output) {
	sha256_transform_avx (&tstate, salt, 1);
	sha256_transform_avx (&tstate, salt + 2, 1);

	__m256i finalblk[2] = {
		_mm256_setr_epi32 (
			0x00000001, 0x80000000, 0, 0, 0, 0, 0, 0
		), _mm256_setr_epi32 (
			0, 0, 0, 0, 0, 0, 0, 0x00000620
		)
	};

	sha256_transform_avx (&tstate, finalblk, 0);

	__m256i buf[2] = {
		tstate
		, _mm256_setr_epi32 (
			0x80000000, 0, 0, 0, 0, 0, 0, 0x00000300 //outerpad
		)
	};

	sha256_transform_avx (&ostate, buf, 0);

	const __m256i swab = _mm256_setr_epi8 (
		0x03, 0x02, 0x01, 0x00,
		0x07, 0x06, 0x05, 0x04,
		0x0b, 0x0a, 0x09, 0x08,
		0x0f, 0x0e, 0x0d, 0x0c,

		0x03, 0x02, 0x01, 0x00,
		0x07, 0x06, 0x05, 0x04,
		0x0b, 0x0a, 0x09, 0x08,
		0x0f, 0x0e, 0x0d, 0x0c
	);

	*(__m256i*) output =  _mm256_shuffle_epi8 (ostate, swab);
}

static __m256i speedupSalsaCalcX[16];

extern "C" void asm_salsa8_parallel_xor (const uint64_t* input, uint64_t* output);
extern "C" void asm_salsa8_parallel_gather (const __m256i* output, __m256i* calcX);

static void xor_prepare_salsa8_parallel (__m256i input[2 * SCRYPT_THREAD_COUNT], __m256i output[2 * SCRYPT_THREAD_COUNT], uint32_t threadLen) {
#ifdef SCRYPT_USE_ASM
	asm_salsa8_parallel_xor ((uint64_t*) &input[0], (uint64_t*) &output[0]);
	asm_salsa8_parallel_gather (output, speedupSalsaCalcX);
#else //SCRYPT_USE_ASM
	//8x input[0] -> x00..08 (xorX[thread*2 + 0]), input[1] -> x09..x15 (xorX[thread*2 + 1])
	//__m256i xorX[16] = {
		//thread 0
		output[0 * threadLen + 0] = _mm256_xor_si256 (output[0 * threadLen + 0], input[0 * threadLen + 0]);
		output[0 * threadLen + 1] = _mm256_xor_si256 (output[0 * threadLen + 1], input[0 * threadLen + 1]);
		//thread 1
		output[1 * threadLen + 0] = _mm256_xor_si256 (output[1 * threadLen + 0], input[1 * threadLen + 0]);
		output[1 * threadLen + 1] = _mm256_xor_si256 (output[1 * threadLen + 1], input[1 * threadLen + 1]);
		//thread 2
		output[2 * threadLen + 0] = _mm256_xor_si256 (output[2 * threadLen + 0], input[2 * threadLen + 0]);
		output[2 * threadLen + 1] = _mm256_xor_si256 (output[2 * threadLen + 1], input[2 * threadLen + 1]);
		//thread 3
		output[3 * threadLen + 0] = _mm256_xor_si256 (output[3 * threadLen + 0], input[3 * threadLen + 0]);
		output[3 * threadLen + 1] = _mm256_xor_si256 (output[3 * threadLen + 1], input[3 * threadLen + 1]);
		//thread 4
		output[4 * threadLen + 0] = _mm256_xor_si256 (output[4 * threadLen + 0], input[4 * threadLen + 0]);
		output[4 * threadLen + 1] = _mm256_xor_si256 (output[4 * threadLen + 1], input[4 * threadLen + 1]);
		//thread 5
		output[5 * threadLen + 0] = _mm256_xor_si256 (output[5 * threadLen + 0], input[5 * threadLen + 0]);
		output[5 * threadLen + 1] = _mm256_xor_si256 (output[5 * threadLen + 1], input[5 * threadLen + 1]);
		//thread 6
		output[6 * threadLen + 0] = _mm256_xor_si256 (output[6 * threadLen + 0], input[6 * threadLen + 0]);
		output[6 * threadLen + 1] = _mm256_xor_si256 (output[6 * threadLen + 1], input[6 * threadLen + 1]);
		//thread 7
		output[7 * threadLen + 0] = _mm256_xor_si256 (output[7 * threadLen + 0], input[7 * threadLen + 0]);
		output[7 * threadLen + 1] = _mm256_xor_si256 (output[7 * threadLen + 1], input[7 * threadLen + 1]);
	//};

	//Transpose matrix (calcX[i] = xorX[0].m256i_u32[i] <= i=0..7, calcX[i] = xorX[1].m256i_u32[i-8] <= i=8..15)
	const __m256i vindex = _mm256_setr_epi32 (0, threadLen * 8, 2 * threadLen * 8, 3 * threadLen * 8, 4 * threadLen * 8, 5 * threadLen * 8, 6 * threadLen * 8, 7 * threadLen * 8);
	const int* xBase = (const int*) output;

	speedupSalsaCalcX[0] = _mm256_i32gather_epi32 (xBase, vindex, 4);
	speedupSalsaCalcX[1] = _mm256_i32gather_epi32 (xBase + 1, vindex, 4);
	speedupSalsaCalcX[2] = _mm256_i32gather_epi32 (xBase + 2, vindex, 4);
	speedupSalsaCalcX[3] = _mm256_i32gather_epi32 (xBase + 3, vindex, 4);
	speedupSalsaCalcX[4] = _mm256_i32gather_epi32 (xBase + 4, vindex, 4);
	speedupSalsaCalcX[5] = _mm256_i32gather_epi32 (xBase + 5, vindex, 4);
	speedupSalsaCalcX[6] = _mm256_i32gather_epi32 (xBase + 6, vindex, 4);
	speedupSalsaCalcX[7] = _mm256_i32gather_epi32 (xBase + 7, vindex, 4);

	speedupSalsaCalcX[8] = _mm256_i32gather_epi32 (xBase + 8, vindex, 4);
	speedupSalsaCalcX[9] = _mm256_i32gather_epi32 (xBase + 9, vindex, 4);
	speedupSalsaCalcX[10] = _mm256_i32gather_epi32 (xBase + 10, vindex, 4);
	speedupSalsaCalcX[11] = _mm256_i32gather_epi32 (xBase + 11, vindex, 4);
	speedupSalsaCalcX[12] = _mm256_i32gather_epi32 (xBase + 12, vindex, 4);
	speedupSalsaCalcX[13] = _mm256_i32gather_epi32 (xBase + 13, vindex, 4);
	speedupSalsaCalcX[14] = _mm256_i32gather_epi32 (xBase + 14, vindex, 4);
	speedupSalsaCalcX[15] = _mm256_i32gather_epi32 (xBase + 15, vindex, 4);
#endif //SCRYPT_USE_ASM
}

static void xor_salsa8_parallel () {
	//#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define R(calcX, res, add1, add2, shift)															\
		calcX[res] = _mm256_xor_si256 (																\
			calcX[res],																				\
			_mm256_or_si256 (																		\
				_mm256_slli_epi32 (_mm256_add_epi32 (calcX[add1], calcX[add2]), shift),				\
				_mm256_srli_epi32 (_mm256_add_epi32 (calcX[add1], calcX[add2]), 32 - shift)			\
			)																						\
		)

#define SALSA_STEP(calcX)													\
		R (calcX, 4, 0, 12, 7);		R (calcX, 9, 5, 1, 7);					\
		R (calcX, 14, 10, 6, 7);	R (calcX, 3, 15, 11, 7);				\
		R (calcX, 8, 4, 0, 9);		R (calcX, 13, 9, 5, 9);					\
		R (calcX, 2, 14, 10, 9);	R (calcX, 7, 3, 15, 9);					\
		R (calcX, 12, 8, 4, 13);	R (calcX, 1, 13, 9, 13);				\
		R (calcX, 6, 2, 14, 13);	R (calcX, 11, 7, 3, 13);				\
		R (calcX, 0, 12, 8, 18);	R (calcX, 5, 1, 13, 18);				\
		R (calcX, 10, 6, 2, 18);	R (calcX, 15, 11, 7, 18);				\
																			\
		R (calcX, 1, 0, 3, 7);		R (calcX, 6, 5, 4, 7);					\
		R (calcX, 11, 10, 9, 7);	R (calcX, 12, 15, 14, 7);				\
		R (calcX, 2, 1, 0, 9);		R (calcX, 7, 6, 5, 9);					\
		R (calcX, 8, 11, 10, 9);	R (calcX, 13, 12, 15, 9);				\
		R (calcX, 3, 2, 1, 13);		R (calcX, 4, 7, 6, 13);					\
		R (calcX, 9, 8, 11, 13);	R (calcX, 14, 13, 12, 13);				\
		R (calcX, 0, 3, 2, 18);		R (calcX, 5, 4, 7, 18);					\
		R (calcX, 10, 9, 8, 18);	R (calcX, 15, 14, 13, 18);

	SALSA_STEP (speedupSalsaCalcX);
	SALSA_STEP (speedupSalsaCalcX);
	SALSA_STEP (speedupSalsaCalcX);
	SALSA_STEP (speedupSalsaCalcX);

#undef SALSA_STEP
#undef R
}

static void xor_postprocess_salsa8_parallel (__m256i input[2 * SCRYPT_THREAD_COUNT], __m256i output[2 * SCRYPT_THREAD_COUNT], uint32_t threadLen) {
	//Transpose back (gather thread results -> xX[i] = calcX[0..7].m256i_u32[i], and xX[i + 8] = calcX[8..15].m256i_u32[i])
	const __m256i vindex2 = _mm256_setr_epi32 (0, 8, 16, 24, 32, 40, 48, 56);
	const int* calcXBase = (const int*) speedupSalsaCalcX;

	//Calculate output
	//Thread 0
	output[0 * threadLen + 0] = _mm256_add_epi32 (output[0 * threadLen + 0], _mm256_i32gather_epi32 (calcXBase + 0 * 8 + 0, vindex2, 4));
	output[0 * threadLen + 1] = _mm256_add_epi32 (output[0 * threadLen + 1], _mm256_i32gather_epi32 (calcXBase + 8 * 8 + 0, vindex2, 4));
	//Thread 1
	output[1 * threadLen + 0] = _mm256_add_epi32 (output[1 * threadLen + 0], _mm256_i32gather_epi32 (calcXBase + 0 * 8 + 1, vindex2, 4));
	output[1 * threadLen + 1] = _mm256_add_epi32 (output[1 * threadLen + 1], _mm256_i32gather_epi32 (calcXBase + 8 * 8 + 1, vindex2, 4));
	//Thread 2
	output[2 * threadLen + 0] = _mm256_add_epi32 (output[2 * threadLen + 0], _mm256_i32gather_epi32 (calcXBase + 0 * 8 + 2, vindex2, 4));
	output[2 * threadLen + 1] = _mm256_add_epi32 (output[2 * threadLen + 1], _mm256_i32gather_epi32 (calcXBase + 8 * 8 + 2, vindex2, 4));
	//Thread 3
	output[3 * threadLen + 0] = _mm256_add_epi32 (output[3 * threadLen + 0], _mm256_i32gather_epi32 (calcXBase + 0 * 8 + 3, vindex2, 4));
	output[3 * threadLen + 1] = _mm256_add_epi32 (output[3 * threadLen + 1], _mm256_i32gather_epi32 (calcXBase + 8 * 8 + 3, vindex2, 4));
	//Thread 4
	output[4 * threadLen + 0] = _mm256_add_epi32 (output[4 * threadLen + 0], _mm256_i32gather_epi32 (calcXBase + 0 * 8 + 4, vindex2, 4));
	output[4 * threadLen + 1] = _mm256_add_epi32 (output[4 * threadLen + 1], _mm256_i32gather_epi32 (calcXBase + 8 * 8 + 4, vindex2, 4));
	//Thread 5
	output[5 * threadLen + 0] = _mm256_add_epi32 (output[5 * threadLen + 0], _mm256_i32gather_epi32 (calcXBase + 0 * 8 + 5, vindex2, 4));
	output[5 * threadLen + 1] = _mm256_add_epi32 (output[5 * threadLen + 1], _mm256_i32gather_epi32 (calcXBase + 8 * 8 + 5, vindex2, 4));
	//Thread 6
	output[6 * threadLen + 0] = _mm256_add_epi32 (output[6 * threadLen + 0], _mm256_i32gather_epi32 (calcXBase + 0 * 8 + 6, vindex2, 4));
	output[6 * threadLen + 1] = _mm256_add_epi32 (output[6 * threadLen + 1], _mm256_i32gather_epi32 (calcXBase + 8 * 8 + 6, vindex2, 4));
	//Thread 7
	output[7 * threadLen + 0] = _mm256_add_epi32 (output[7 * threadLen + 0], _mm256_i32gather_epi32 (calcXBase + 0 * 8 + 7, vindex2, 4));
	output[7 * threadLen + 1] = _mm256_add_epi32 (output[7 * threadLen + 1], _mm256_i32gather_epi32 (calcXBase + 8 * 8 + 7, vindex2, 4));
}

static __m256i speedupScryptV[1024 * 4 * SCRYPT_THREAD_COUNT];

static void scrypt_core (__m256i X[4 * SCRYPT_THREAD_COUNT]) {

#define CORE1_PRE_STEP(step, i)				 				\
		XPtr = &X[step * 4];								\
		VPtr = &speedupScryptV[(step * N + i) * 4];			\
		VPtr[0] = XPtr[0];									\
		VPtr[1] = XPtr[1];									\
		VPtr[2] = XPtr[2];									\
		VPtr[3] = XPtr[3];

#define CORE2_PRE_STEP(step) 										\
		j = 4 * (X[step * 4 + 2].m256i_u32[0] & (N - 1));			\
		XPtr = &X[step * 4];										\
		VPtr = &speedupScryptV[step * N * 4 + j];					\
		XPtr[0] = _mm256_xor_si256 (XPtr[0], VPtr[0]);				\
		XPtr[1] = _mm256_xor_si256 (XPtr[1], VPtr[1]);				\
		XPtr[2] = _mm256_xor_si256 (XPtr[2], VPtr[2]);				\
		XPtr[3] = _mm256_xor_si256 (XPtr[3], VPtr[3]);

	const int32_t N = 1024;
	__m256i* XPtr;
	__m256i* VPtr;

	for (uint32_t i = 0; i < N; i++) {
		CORE1_PRE_STEP (0, i);
		CORE1_PRE_STEP (1, i);
		CORE1_PRE_STEP (2, i);
		CORE1_PRE_STEP (3, i);
		CORE1_PRE_STEP (4, i);
		CORE1_PRE_STEP (5, i);
		CORE1_PRE_STEP (6, i);
		CORE1_PRE_STEP (7, i);

		xor_prepare_salsa8_parallel (&X[2], &X[0], 4);
		xor_salsa8_parallel ();
		xor_postprocess_salsa8_parallel (&X[2], &X[0], 4);

		xor_prepare_salsa8_parallel (&X[0], &X[2], 4);
		xor_salsa8_parallel ();
		xor_postprocess_salsa8_parallel (&X[0], &X[2], 4);
	}

	for (uint32_t i = 0; i < N; i++) {
		uint32_t j;

		CORE2_PRE_STEP (0);
		CORE2_PRE_STEP (1);
		CORE2_PRE_STEP (2);
		CORE2_PRE_STEP (3);
		CORE2_PRE_STEP (4);
		CORE2_PRE_STEP (5);
		CORE2_PRE_STEP (6);
		CORE2_PRE_STEP (7);

		xor_prepare_salsa8_parallel (&X[2], &X[0], 4);
		xor_salsa8_parallel ();
		xor_postprocess_salsa8_parallel (&X[2], &X[0], 4);

		xor_prepare_salsa8_parallel (&X[0], &X[2], 4);
		xor_salsa8_parallel ();
		xor_postprocess_salsa8_parallel (&X[0], &X[2], 4);
	}

#undef CORE1_STEP
#undef CORE2_STEP
}

static void scrypt_1024_1_1_256 (const uint32_t *input, uint32_t *output, const __m256i midstate[8]) {
	__m256i ostate[SCRYPT_THREAD_COUNT];
	__m256i X[4 * SCRYPT_THREAD_COUNT];

	__m256i tstate[SCRYPT_THREAD_COUNT] = {
		midstate[0], midstate[1], midstate[2], midstate[3], midstate[4], midstate[5], midstate[6], midstate[7]
	};

	HMAC_SHA256_80_init (&input[0 * 20], tstate[0], ostate[0]);
	HMAC_SHA256_80_init (&input[1 * 20], tstate[1], ostate[1]);
	HMAC_SHA256_80_init (&input[2 * 20], tstate[2], ostate[2]);
	HMAC_SHA256_80_init (&input[3 * 20], tstate[3], ostate[3]);
	HMAC_SHA256_80_init (&input[4 * 20], tstate[4], ostate[4]);
	HMAC_SHA256_80_init (&input[5 * 20], tstate[5], ostate[5]);
	HMAC_SHA256_80_init (&input[6 * 20], tstate[6], ostate[6]);
	HMAC_SHA256_80_init (&input[7 * 20], tstate[7], ostate[7]);

	PBKDF2_SHA256_80_128 (tstate[0], ostate[0], &input[0 * 20], &X[0 * 4]);
	PBKDF2_SHA256_80_128 (tstate[1], ostate[1], &input[1 * 20], &X[1 * 4]);
	PBKDF2_SHA256_80_128 (tstate[2], ostate[2], &input[2 * 20], &X[2 * 4]);
	PBKDF2_SHA256_80_128 (tstate[3], ostate[3], &input[3 * 20], &X[3 * 4]);
	PBKDF2_SHA256_80_128 (tstate[4], ostate[4], &input[4 * 20], &X[4 * 4]);
	PBKDF2_SHA256_80_128 (tstate[5], ostate[5], &input[5 * 20], &X[5 * 4]);
	PBKDF2_SHA256_80_128 (tstate[6], ostate[6], &input[6 * 20], &X[6 * 4]);
	PBKDF2_SHA256_80_128 (tstate[7], ostate[7], &input[7 * 20], &X[7 * 4]);

	scrypt_core (X);

	PBKDF2_SHA256_128_32 (tstate[0], ostate[0], &X[0 * 4], &output[0 * 8]);
	PBKDF2_SHA256_128_32 (tstate[1], ostate[1], &X[1 * 4], &output[1 * 8]);
	PBKDF2_SHA256_128_32 (tstate[2], ostate[2], &X[2 * 4], &output[2 * 8]);
	PBKDF2_SHA256_128_32 (tstate[3], ostate[3], &X[3 * 4], &output[3 * 8]);
	PBKDF2_SHA256_128_32 (tstate[4], ostate[4], &X[4 * 4], &output[4 * 8]);
	PBKDF2_SHA256_128_32 (tstate[5], ostate[5], &X[5 * 4], &output[5 * 8]);
	PBKDF2_SHA256_128_32 (tstate[6], ostate[6], &X[6 * 4], &output[6 * 8]);
	PBKDF2_SHA256_128_32 (tstate[7], ostate[7], &X[7 * 4], &output[7 * 8]);
}

//Speedup cypher caller

uint32_t initSpeedupCypher () {
	return SCRYPT_THREAD_COUNT; //Step count
}

void releaseSpeedupCypher () {
}

void speedupCypher (const uint32_t* input, uint32_t* output) {
	ALIGN_PREFIX (32) uint32_t midstate[8 * SCRYPT_THREAD_COUNT] = { 1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8 }; //test values

	scrypt_1024_1_1_256 (input, output, (const __m256i*) midstate);

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
