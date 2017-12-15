#define _CRT_SECURE_NO_WARNINGS

#include <stdint.h>
#include <intrin.h>
#include <cstring>
#include <cassert>
#include <cstdio>

#	define ALIGN_PREFIX(x) __declspec(align(x))
#	define ALIGN_POSTFIX(x)

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

static void scrypt_core (uint32_t* X) {
	const int32_t N = 1024;
	ALIGN_PREFIX (32) uint32_t V[1024 * 32 * sizeof (uint32_t)] ALIGN_POSTFIX (32); //1024*128

	for (uint32_t i = 0; i < N; i++) {
		__m256i* srcX = (__m256i*) &X[0];
		__m256i* destV = (__m256i*) &V[i * 32];

		//memcpy (&V[i * 32], X, 128);
		_mm256_store_si256 (destV++, srcX[0]);
		_mm256_store_si256 (destV++, srcX[1]);
		_mm256_store_si256 (destV++, srcX[2]);
		_mm256_store_si256 (destV, srcX[3]);

		//xor_salsa8 (&X[0], &X[16]);
		xor_salsa8 (srcX[2], srcX[3], srcX[0], srcX[1]); //The order of the input and output parameters turned!!!

		 //xor_salsa8 (&X[16], &X[0]);
		xor_salsa8 (srcX[0], srcX[1], srcX[2], srcX[3]);
	}

	for (uint32_t i = 0; i < N; i++) {
		uint32_t j = 32 * (X[16] & (N - 1));

		//for (uint32_t k = 0; k < 32; k++) {
		//	X[k] ^= V[j + k];
		//}
		__m256i* srcV = (__m256i*) &V[j];
		__m256i* destX = (__m256i*) &X[0];
		destX[0] = _mm256_xor_si256 (destX[0], *srcV++);
		destX[1] = _mm256_xor_si256 (destX[1], *srcV++);
		destX[2] = _mm256_xor_si256 (destX[2], *srcV++);
		destX[3] = _mm256_xor_si256 (destX[3], *srcV);

		//xor_salsa8 (&X[0], &X[16]);
		xor_salsa8 (destX[2], destX[3], destX[0], destX[1]); //The order of the input and output parameters turned!!!

		//xor_salsa8 (&X[16], &X[0]);
		xor_salsa8 (destX[0], destX[1], destX[2], destX[3]);
	}
}

static void scrypt_1024_1_1_256 (const uint32_t *input, uint32_t *output, uint32_t *midstate, unsigned char *scratchpad, int N) {
	assert (N == 1024);

	uint32_t tstate[8], ostate[8];
	ALIGN_PREFIX (128) uint32_t X[32] ALIGN_POSTFIX (128);

	memcpy (tstate, midstate, 32);
	HMAC_SHA256_80_init (input, tstate, ostate);
	PBKDF2_SHA256_80_128 (tstate, ostate, input, X);

	scrypt_core (X);

	PBKDF2_SHA256_128_32 (tstate, ostate, X, output);
}

//Speedup cypher caller

#define SCRYPT_ITERATION_COUNT 1024

uint32_t initSpeedupCypher () {
	return 1; //Step count
}

void releaseSpeedupCypher () {
}

void speedupCypher (uint32_t stepCount, const uint32_t* input, uint32_t* output, size_t sourceIntegerCount, size_t targetIntegerCount) {
	uint32_t midstate[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }; //test values

	scrypt_1024_1_1_256 (input, output, midstate, NULL, SCRYPT_ITERATION_COUNT);

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
