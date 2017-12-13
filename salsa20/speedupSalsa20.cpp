#include <stdint.h>
#include <intrin.h>
#include <cstring>

void speedupSalsa8 (const uint32_t input[16], uint32_t output[16]) {
	//__m256i output0 = _mm256_setr_epi32 (output[0], output[1], output[2], output[3], output[4], output[5], output[6], output[7]);
	//__m256i output1 = _mm256_setr_epi32 (output[8], output[9], output[10], output[11], output[12], output[13], output[14], output[15]);

	//__m256i input0 = _mm256_setr_epi32 (input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7]);
	//__m256i input1 = _mm256_setr_epi32 (input[8], input[9], input[10], input[11], input[12], input[13], input[14], input[15]);

	__m256i output0 = _mm256_loadu_si256 ((__m256i const*) &output[0]);
	__m256i output1 = _mm256_loadu_si256 ((__m256i const*) &output[8]);

	const __m256i input0 = _mm256_loadu_si256 ((__m256i const*) &input[0]);
	const __m256i input1 = _mm256_loadu_si256 ((__m256i const*) &input[8]);

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

	//for (int step = 0; step < 8; step += 2) {
	//	/* Operate on columns. */
	//	//x04 ^= R (x00 + x12, 7);	x09 ^= R (x05 + x01, 7);
	//	//x14 ^= R (x10 + x06, 7);	x03 ^= R (x15 + x11, 7);
	//	x04 ^= _rorx_u32 (x00 + x12, 32 - 7);	x09 ^= _rorx_u32 (x05 + x01, 32 - 7);
	//	x14 ^= _rorx_u32 (x10 + x06, 32 - 7);	x03 ^= _rorx_u32 (x15 + x11, 32 - 7);

	//	//x08 ^= R (x04 + x00, 9);	x13 ^= R (x09 + x05, 9);
	//	//x02 ^= R (x14 + x10, 9);	x07 ^= R (x03 + x15, 9);
	//	x08 ^= _rorx_u32 (x04 + x00, 32 - 9);	x13 ^= _rorx_u32 (x09 + x05, 32 - 9);
	//	x02 ^= _rorx_u32 (x14 + x10, 32 - 9);	x07 ^= _rorx_u32 (x03 + x15, 32 - 9);

	//	//x12 ^= R (x08 + x04, 13);	x01 ^= R (x13 + x09, 13);
	//	//x06 ^= R (x02 + x14, 13);	x11 ^= R (x07 + x03, 13);
	//	x12 ^= _rorx_u32 (x08 + x04, 32 - 13);	x01 ^= _rorx_u32 (x13 + x09, 32 - 13);
	//	x06 ^= _rorx_u32 (x02 + x14, 32 - 13);	x11 ^= _rorx_u32 (x07 + x03, 32 - 13);

	//	//x00 ^= R (x12 + x08, 18);	x05 ^= R (x01 + x13, 18);
	//	//x10 ^= R (x06 + x02, 18);	x15 ^= R (x11 + x07, 18);
	//	x00 ^= _rorx_u32 (x12 + x08, 32 - 18);	x05 ^= _rorx_u32 (x01 + x13, 32 - 18);
	//	x10 ^= _rorx_u32 (x06 + x02, 32 - 18);	x15 ^= _rorx_u32 (x11 + x07, 32 - 18);

	//	///* Operate on rows. */
	//	//x01 ^= R (x00 + x03, 7);	x06 ^= R (x05 + x04, 7);
	//	//x11 ^= R (x10 + x09, 7);	x12 ^= R (x15 + x14, 7);
	//	x01 ^= _rorx_u32 (x00 + x03, 32 - 7);	x06 ^= _rorx_u32 (x05 + x04, 32 - 7);
	//	x11 ^= _rorx_u32 (x10 + x09, 32 - 7);	x12 ^= _rorx_u32 (x15 + x14, 32 - 7);

	//	//x02 ^= R (x01 + x00, 9);	x07 ^= R (x06 + x05, 9);
	//	//x08 ^= R (x11 + x10, 9);	x13 ^= R (x12 + x15, 9);
	//	x02 ^= _rorx_u32 (x01 + x00, 32 - 9);	x07 ^= _rorx_u32 (x06 + x05, 32 - 9);
	//	x08 ^= _rorx_u32 (x11 + x10, 32 - 9);	x13 ^= _rorx_u32 (x12 + x15, 32 - 9);

	//	//x03 ^= R (x02 + x01, 13);	x04 ^= R (x07 + x06, 13);
	//	//x09 ^= R (x08 + x11, 13);	x14 ^= R (x13 + x12, 13);
	//	x03 ^= _rorx_u32 (x02 + x01, 32 - 13);	x04 ^= _rorx_u32 (x07 + x06, 32 - 13);
	//	x09 ^= _rorx_u32 (x08 + x11, 32 - 13);	x14 ^= _rorx_u32 (x13 + x12, 32 - 13);

	//	//x00 ^= R (x03 + x02, 18);	x05 ^= R (x04 + x07, 18);
	//	//x10 ^= R (x09 + x08, 18);	x15 ^= R (x14 + x13, 18);
	//	x00 ^= _rorx_u32 (x03 + x02, 32 - 18);	x05 ^= _rorx_u32 (x04 + x07, 32 - 18);
	//	x10 ^= _rorx_u32 (x09 + x08, 32 - 18);	x15 ^= _rorx_u32 (x14 + x13, 32 - 18);
	//}

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

	output0 = _mm256_add_epi32 (output0, x0);
	output1 = _mm256_add_epi32 (output1, x1);

	//memcpy (&output[0], &output0.m256i_u32[0], 8 * sizeof (uint32_t));
	//memcpy (&output[8], &output1.m256i_u32[0], 8 * sizeof (uint32_t));

	_mm256_storeu_si256 ((__m256i*) &output[0], output0);
	_mm256_storeu_si256 ((__m256i*) &output[8], output1);
}
