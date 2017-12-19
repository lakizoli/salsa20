#define _CRT_SECURE_NO_WARNINGS

#include <memory.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#	define ALIGN_PREFIX(x) __declspec(align(x))
#	define ALIGN_POSTFIX(x)

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

extern void sha256_transform (uint32_t *state, const uint32_t *block, int swap);
extern void sha256_init (uint32_t *state);

static inline uint32_t swab32 (uint32_t v) {
	return _byteswap_ulong (v);
}

static inline void HMAC_SHA256_80_init (const uint32_t *key,
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

static inline void PBKDF2_SHA256_80_128 (const uint32_t *tstate,
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

static inline void PBKDF2_SHA256_128_32 (uint32_t *tstate, uint32_t *ostate,
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

static void xor_salsa8 (uint32_t B[16], const uint32_t Bx[16]) {
	uint32_t x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, x11, x12, x13, x14, x15;
	int i;

	x00 = (B[0] ^= Bx[0]);
	x01 = (B[1] ^= Bx[1]);
	x02 = (B[2] ^= Bx[2]);
	x03 = (B[3] ^= Bx[3]);
	x04 = (B[4] ^= Bx[4]);
	x05 = (B[5] ^= Bx[5]);
	x06 = (B[6] ^= Bx[6]);
	x07 = (B[7] ^= Bx[7]);
	x08 = (B[8] ^= Bx[8]);
	x09 = (B[9] ^= Bx[9]);
	x10 = (B[10] ^= Bx[10]);
	x11 = (B[11] ^= Bx[11]);
	x12 = (B[12] ^= Bx[12]);
	x13 = (B[13] ^= Bx[13]);
	x14 = (B[14] ^= Bx[14]);
	x15 = (B[15] ^= Bx[15]);
	for (i = 0; i < 8; i += 2) {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns. */
		x04 ^= R (x00 + x12, 7);	x09 ^= R (x05 + x01, 7);
		x14 ^= R (x10 + x06, 7);	x03 ^= R (x15 + x11, 7);

		x08 ^= R (x04 + x00, 9);	x13 ^= R (x09 + x05, 9);
		x02 ^= R (x14 + x10, 9);	x07 ^= R (x03 + x15, 9);

		x12 ^= R (x08 + x04, 13);	x01 ^= R (x13 + x09, 13);
		x06 ^= R (x02 + x14, 13);	x11 ^= R (x07 + x03, 13);

		x00 ^= R (x12 + x08, 18);	x05 ^= R (x01 + x13, 18);
		x10 ^= R (x06 + x02, 18);	x15 ^= R (x11 + x07, 18);

		/* Operate on rows. */
		x01 ^= R (x00 + x03, 7);	x06 ^= R (x05 + x04, 7);
		x11 ^= R (x10 + x09, 7);	x12 ^= R (x15 + x14, 7);

		x02 ^= R (x01 + x00, 9);	x07 ^= R (x06 + x05, 9);
		x08 ^= R (x11 + x10, 9);	x13 ^= R (x12 + x15, 9);

		x03 ^= R (x02 + x01, 13);	x04 ^= R (x07 + x06, 13);
		x09 ^= R (x08 + x11, 13);	x14 ^= R (x13 + x12, 13);

		x00 ^= R (x03 + x02, 18);	x05 ^= R (x04 + x07, 18);
		x10 ^= R (x09 + x08, 18);	x15 ^= R (x14 + x13, 18);
#undef R
	}
	B[0] += x00;
	B[1] += x01;
	B[2] += x02;
	B[3] += x03;
	B[4] += x04;
	B[5] += x05;
	B[6] += x06;
	B[7] += x07;
	B[8] += x08;
	B[9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}

static void scrypt_core (uint32_t *X, uint32_t *V, uint32_t N) {
	uint32_t i, j, k;

	for (i = 0; i < N; i++) {
		memcpy (&V[i * 32], X, 128);
		xor_salsa8 (&X[0], &X[16]);
		xor_salsa8 (&X[16], &X[0]);
	}
	for (i = 0; i < N; i++) {
		j = 32 * (X[16] & (N - 1));
		for (k = 0; k < 32; k++)
			X[k] ^= V[j + k];
		xor_salsa8 (&X[0], &X[16]);
		xor_salsa8 (&X[16], &X[0]);
	}
}

static void scrypt_1024_1_1_256 (const uint32_t *input, uint32_t *output, uint32_t *midstate, unsigned char *scratchpad, int N) {
	uint32_t tstate[8], ostate[8];
	ALIGN_PREFIX (128) uint32_t X[32] ALIGN_POSTFIX (128);
	uint32_t *V;

	V = (uint32_t *) (((uintptr_t) (scratchpad) +63) & ~(uintptr_t) (63));

	memcpy (tstate, midstate, 32);
	HMAC_SHA256_80_init (input, tstate, ostate);
	PBKDF2_SHA256_80_128 (tstate, ostate, input, X);

	scrypt_core (X, V, N);

	PBKDF2_SHA256_128_32 (tstate, ostate, X, output);
}

//Utility functions

#define SCRYPT_MAX_WAYS 1
#define SCRYPT_ITERATION_COUNT 1024

unsigned char *scrypt_buffer_alloc (int N) {
	return malloc ((size_t) N * SCRYPT_MAX_WAYS * 128 + 63);
}

//Reference cypher caller

unsigned char* g_reference_scratchpad = NULL;

uint32_t initReferenceCypher () {
	if (g_reference_scratchpad == NULL) {
		g_reference_scratchpad = scrypt_buffer_alloc (SCRYPT_ITERATION_COUNT);
	}
	return SCRYPT_MAX_WAYS;
}

void releaseReferenceCypher () {
	if (g_reference_scratchpad) {
		free (g_reference_scratchpad);
		g_reference_scratchpad = NULL;
	}
}

void referenceCypher (uint32_t stepCount, const uint32_t* input, uint32_t* output, size_t sourceIntegerCount, size_t targetIntegerCount) {
	assert (stepCount == 1);

	uint32_t midstate[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }; //test values

	scrypt_1024_1_1_256 (input, output, midstate, g_reference_scratchpad, SCRYPT_ITERATION_COUNT);

	////TEST
	//FILE* fout = fopen ("d:\\work\\salsa2\\orig.dat", "ab"); //"wb" to delete content
	//if (fout) {
	//	for (int i = 0; i < targetIntegerCount; ++i) {
	//		fprintf (fout, "0x%08x\n", output[i]);
	//	}
	//	fclose (fout);
	//}
	////END TEST
}
