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

static void HMAC_SHA256_80_init (const uint32_t *key, __m256i& tstate, __m256i& ostate) {
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

#ifdef SCRYPT_USE_ASM
	extern "C" void asm_salsa8_parallel_xor (const __m256i* input, __m256i* output);
	extern "C" void asm_salsa8_parallel_gather (const __m256i* output, __m256i* calcX);
	extern "C" void asm_salsa8_parallel_postprocess (const __m256i* calcX, __m256i* output);
#endif //SCRYPT_USE_ASM

static void xor_prepare_salsa8_parallel (__m256i input[2 * SCRYPT_THREAD_COUNT], __m256i output[2 * SCRYPT_THREAD_COUNT], uint32_t threadLen) {
#ifdef SCRYPT_USE_ASM
	asm_salsa8_parallel_xor (input, output);
	asm_salsa8_parallel_gather (output, speedupSalsaCalcX);
#else //SCRYPT_USE_ASM
	//8x input[0] -> x00..08 (xorX[thread*2 + 0]), input[1] -> x09..x15 (xorX[thread*2 + 1])
	//__m256i xorX[16] = {
		uint8_t i = SCRYPT_THREAD_COUNT;
		while (i--) {
			output[i * threadLen + 0] = _mm256_xor_si256 (output[i * threadLen + 0], input[i * threadLen + 0]);
			output[i * threadLen + 1] = _mm256_xor_si256 (output[i * threadLen + 1], input[i * threadLen + 1]);
		}
	//};

	//Transpose matrix (calcX[i] = xorX[0].m256i_u32[i] <= i=0..7, calcX[i] = xorX[1].m256i_u32[i-8] <= i=8..15)
	const __m256i vindex = _mm256_setr_epi32 (0, threadLen * 8, 2 * threadLen * 8, 3 * threadLen * 8, 4 * threadLen * 8, 5 * threadLen * 8, 6 * threadLen * 8, 7 * threadLen * 8);
	const int* calcX = (const int*) output;

	i = 16;
	while (i--) {
		speedupSalsaCalcX[i] = _mm256_i32gather_epi32 (calcX + i, vindex, 4);
	}
#endif //SCRYPT_USE_ASM
}

static void xor_salsa8_parallel () {
	//#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define R(res, add1, add2, shift)																	\
		calcX[res] = _mm256_xor_si256 (																\
			calcX[res],																				\
			_mm256_or_si256 (																		\
				_mm256_slli_epi32 (_mm256_add_epi32 (calcX[add1], calcX[add2]), shift),				\
				_mm256_srli_epi32 (_mm256_add_epi32 (calcX[add1], calcX[add2]), 32 - shift)			\
			)																						\
		)

#define SALSA_STEP()										\
		R (4, 0, 12, 7);	R (9, 5, 1, 7);					\
		R (14, 10, 6, 7);	R (3, 15, 11, 7);				\
		R (8, 4, 0, 9);		R (13, 9, 5, 9);				\
		R (2, 14, 10, 9);	R (7, 3, 15, 9);				\
		R (12, 8, 4, 13);	R (1, 13, 9, 13);				\
		R (6, 2, 14, 13);	R (11, 7, 3, 13);				\
		R (0, 12, 8, 18);	R (5, 1, 13, 18);				\
		R (10, 6, 2, 18);	R (15, 11, 7, 18);				\
															\
		R (1, 0, 3, 7);		R (6, 5, 4, 7);					\
		R (11, 10, 9, 7);	R (12, 15, 14, 7);				\
		R (2, 1, 0, 9);		R (7, 6, 5, 9);					\
		R (8, 11, 10, 9);	R (13, 12, 15, 9);				\
		R (3, 2, 1, 13);	R (4, 7, 6, 13);				\
		R (9, 8, 11, 13);	R (14, 13, 12, 13);				\
		R (0, 3, 2, 18);	R (5, 4, 7, 18);				\
		R (10, 9, 8, 18);	R (15, 14, 13, 18);

	__m256i* calcX = speedupSalsaCalcX;
	SALSA_STEP ();
	SALSA_STEP ();
	SALSA_STEP ();
	SALSA_STEP ();

#undef SALSA_STEP
#undef R
}

static void xor_postprocess_salsa8_parallel (__m256i output[2 * SCRYPT_THREAD_COUNT], uint32_t threadLen) {
#ifdef SCRYPT_USE_ASM
	asm_salsa8_parallel_postprocess (speedupSalsaCalcX, output);
#else //SCRYPT_USE_ASM
	//Transpose back (gather thread results -> xX[i] = calcX[0..7].m256i_u32[i], and xX[i + 8] = calcX[8..15].m256i_u32[i])
	const __m256i vindex = _mm256_setr_epi32 (0, 8, 16, 24, 32, 40, 48, 56);
	const int* calcX = (const int*) speedupSalsaCalcX;

	//Calculate output
	uint8_t thread = SCRYPT_THREAD_COUNT;
	while (thread--) {
		output[thread * threadLen + 0] = _mm256_add_epi32 (output[thread * threadLen + 0], _mm256_i32gather_epi32 (calcX + 0 * 8 + thread, vindex, 4));
		output[thread * threadLen + 1] = _mm256_add_epi32 (output[thread * threadLen + 1], _mm256_i32gather_epi32 (calcX + 8 * 8 + thread, vindex, 4));
	}
#endif //SCRYPT_USE_ASM
}

static __m256i speedupScryptV[1024 * 4 * SCRYPT_THREAD_COUNT];

static void scrypt_prepare_pass1_step (uint32_t cycle, __m256i X[4 * SCRYPT_THREAD_COUNT]) {
	uint8_t thread = SCRYPT_THREAD_COUNT;
	while (thread--) {
		speedupScryptV[(thread * 1024 + cycle) * 4 + 0] = X[thread * 4 + 0];
		speedupScryptV[(thread * 1024 + cycle) * 4 + 1] = X[thread * 4 + 1];
		speedupScryptV[(thread * 1024 + cycle) * 4 + 2] = X[thread * 4 + 2];
		speedupScryptV[(thread * 1024 + cycle) * 4 + 3] = X[thread * 4 + 3];
	}
}

static void scrypt_prepare_pass2_step (__m256i X[4 * SCRYPT_THREAD_COUNT]) {
	uint8_t thread = SCRYPT_THREAD_COUNT;
	while (thread--) {
		uint32_t j = 4 * (X[thread * 4 + 2].m256i_u32[0] & (1024 - 1));

		__m256i* XPtr = &X[thread * 4];
		XPtr[0] = _mm256_xor_si256 (XPtr[0], speedupScryptV[thread * 1024 * 4 + j + 0]);
		XPtr[1] = _mm256_xor_si256 (XPtr[1], speedupScryptV[thread * 1024 * 4 + j + 1]);
		XPtr[2] = _mm256_xor_si256 (XPtr[2], speedupScryptV[thread * 1024 * 4 + j + 2]);
		XPtr[3] = _mm256_xor_si256 (XPtr[3], speedupScryptV[thread * 1024 * 4 + j + 3]);
	}
}

static void scrypt_core (__m256i X[4 * SCRYPT_THREAD_COUNT]) {
	uint16_t step = 1024;
	while (step--) {
		scrypt_prepare_pass1_step ((uint32_t) 1024 - step - 1, X);

		xor_prepare_salsa8_parallel (&X[2], &X[0], 4);
		xor_salsa8_parallel ();
		xor_postprocess_salsa8_parallel (&X[0], 4);

		xor_prepare_salsa8_parallel (&X[0], &X[2], 4);
		xor_salsa8_parallel ();
		xor_postprocess_salsa8_parallel (&X[2], 4);
	}

	step = 1024;
	while (step--) {
		scrypt_prepare_pass2_step (X);

		xor_prepare_salsa8_parallel (&X[2], &X[0], 4);
		xor_salsa8_parallel ();
		xor_postprocess_salsa8_parallel (&X[0], 4);

		xor_prepare_salsa8_parallel (&X[0], &X[2], 4);
		xor_salsa8_parallel ();
		xor_postprocess_salsa8_parallel (&X[2], 4);
	}
}

static void sp_scrypt_1024_1_1_256 (const uint32_t *input, uint32_t *output, const __m256i midstate[SCRYPT_THREAD_COUNT]) {
	__m256i ostate[SCRYPT_THREAD_COUNT];
	__m256i X[4 * SCRYPT_THREAD_COUNT];

	__m256i tstate[SCRYPT_THREAD_COUNT] = {
		midstate[0], midstate[1], midstate[2], midstate[3], midstate[4], midstate[5], midstate[6], midstate[7]
	};

	uint8_t thread = SCRYPT_THREAD_COUNT;
	while (thread--) {
		HMAC_SHA256_80_init (&input[thread * 20], tstate[thread], ostate[thread]);
		PBKDF2_SHA256_80_128 (tstate[thread], ostate[thread], &input[thread * 20], &X[thread * 4]);
	}

	scrypt_core (X);

	thread = SCRYPT_THREAD_COUNT;
	while (thread--) {
		PBKDF2_SHA256_128_32 (tstate[thread], ostate[thread], &X[thread * 4], &output[thread * 8]);
	}
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
		1, 2, 3, 4, 5, 6, 7, 8
	}; //test values

	sp_scrypt_1024_1_1_256 (input, output, (const __m256i*) midstate);

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
