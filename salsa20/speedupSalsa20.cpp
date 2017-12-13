#include <stdint.h>

void speedupSalsa8 (const uint32_t input[16], uint32_t output[16]) {
	uint32_t x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, x11, x12, x13, x14, x15;
	int i;

	x00 = (output[0] ^= input[0]);
	x01 = (output[1] ^= input[1]);
	x02 = (output[2] ^= input[2]);
	x03 = (output[3] ^= input[3]);
	x04 = (output[4] ^= input[4]);
	x05 = (output[5] ^= input[5]);
	x06 = (output[6] ^= input[6]);
	x07 = (output[7] ^= input[7]);
	x08 = (output[8] ^= input[8]);
	x09 = (output[9] ^= input[9]);
	x10 = (output[10] ^= input[10]);
	x11 = (output[11] ^= input[11]);
	x12 = (output[12] ^= input[12]);
	x13 = (output[13] ^= input[13]);
	x14 = (output[14] ^= input[14]);
	x15 = (output[15] ^= input[15]);
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
	output[0] += x00;
	output[1] += x01;
	output[2] += x02;
	output[3] += x03;
	output[4] += x04;
	output[5] += x05;
	output[6] += x06;
	output[7] += x07;
	output[8] += x08;
	output[9] += x09;
	output[10] += x10;
	output[11] += x11;
	output[12] += x12;
	output[13] += x13;
	output[14] += x14;
	output[15] += x15;
}
