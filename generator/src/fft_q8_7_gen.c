/*
 * fft_f32_gen.c
 *
 *  Created on: 28 Nov 2017
 *      Author: Ahmed.Z
 */
#include <stdio.h>
#include <math.h>

#include "fft_q8_7.h"
#include "fft_gen.h"


static void twiddle_factor_Q8_7(size_t N)
{
	printf("static const int8_t twiddle_factor_re[%zu]={\n", N);

	for (size_t k = 0; k < N/2; ++k) {
		float temp = cos(-2*PI*k/N) * (1 << Q8_7_SHIFT);
		if(temp == (1 << Q8_7_SHIFT))
			temp=temp-1;
		printf("0x%02hhx, ", (int8_t) temp);
		if (!((k + 1) % 8)) printf("\n");
	}
	printf("};\n");

	printf("static const int8_t twiddle_factor_im[%zu]={\n", N);

	for (size_t k = 0; k < N/2; ++k) {
		float temp = sin(-2*PI*k/N) * (1 << Q8_7_SHIFT);
		if(temp == (1 << Q8_7_SHIFT))
			temp=temp-1;
		printf("0x%02hhx, ", (int8_t) temp );
		if (!((k + 1) % 8)) printf("\n");
	}
	printf("};\n");
}

static void bit_reversal_Q8_7(size_t N) {
	bit_reversal_type("Q8_7_t", N);
}

void fft_q8_7_gen(size_t N){

	printf("/* GENERATED CODE BEGIN */\n");
	printf("#define LOG_2_FFT_X_N (%zu)\n", log_2(N));
	printf("/* GENERATED CODE END */\n");

	printf("/* GENERATED CODE BEGIN */\n");
	printf("static const Q8_7_t PI_Q8_7 = 0x%04hx;\n", (Q8_7_t) (PI * (1 << Q8_7_SHIFT)));
	twiddle_factor_Q8_7(N);
	bit_reversal_Q8_7(N);
	printf("/* GENERATED CODE END */\n");
}
