/*
 * fft_f32_gen.c
 *
 *  Created on: 28 Nov 2017
 *      Author: Ahmed.Z
 */
#include <stdio.h>
#include <math.h>

#include "fft_f32.h"
#include "fft_gen.h"

static void twiddle_factor_float32(size_t N)
{
	printf("static const float32_t twiddle_factor_re[%zu]={\n", N);

	for (size_t k = 0; k < N/2; ++k) {
		printf("%f, ", cos(-2*PI*k/N) );

		if (!((k + 1) % 8)) printf("\n");
	}
	printf("};\n");

	printf("static const float32_t twiddle_factor_im[%zu]={\n", N);

	for (size_t k = 0; k < N/2; ++k) {
		printf("%f, ", sin(-2*PI*k/N) );

		if (!((k + 1) % 8)) printf("\n");
	}
	printf("};\n");
}

static void bit_reversal_float32(size_t N) {
	bit_reversal_type("float32_t", N);
}

void fft_f32_gen(size_t N){

	printf("/* GENERATED CODE BEGIN */\n");
	printf("#define LOG_2_FFT_X_N (%zu)\n", log_2(N));
	printf("/* GENERATED CODE END */\n");

	printf("/* GENERATED CODE BEGIN */\n");
	printf("static const float32_t PI_F32 = 3.14159265359f;\n");
	twiddle_factor_float32(N);
	bit_reversal_float32(N);
	printf("/* GENERATED CODE END */\n");
}
