/*
 * fft.c
 *
 *  Created on: 27 Nov 2017
 *      Author: Ahmed.Z
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fft_gen.h"

const float PI = 3.14159265359f;

bool is_power_2(size_t N) {
	return ((N != 0) && !(N & (N - 1)));
}

size_t log_2(size_t N) {
	size_t r = 0;

	while (N >>= 1) {
		r++;
	}
	return r;
}

void bit_reversal_type(const char *type, size_t N) {

	size_t idx[N];
	for (size_t i = 0; i < N; ++i) {
		idx[i] = i;
	}

	recursive_bit_reversal(idx, N);

	printf("__attribute__((always_inline))\n"
			"static inline void bit_reversal(Complex_t *X){\n");
	printf("    %s tmp;\n", type);
	for (size_t n = 0; n < N; ++n) {
		if (n < idx[n]) {
			printf(
					"    tmp = X[%3zu].re; X[%3zu].re = X[%3zu].re; X[%3zu].re = tmp;\n",
					n, n, idx[n], idx[n]);
		}
	}
	printf("}\n");
}

void recursive_bit_reversal(size_t *idx, size_t N) {

	if (N == 1) {
		return;
	}

	size_t M = N / 2;
	size_t idx_odd[M];
	//Make a temporary copy of the odd
	for (size_t m = 0; m < M; m++) {
		idx_odd[m] = idx[2 * m + 1];
	}

	for (size_t m = 0; m < M; m++) {
		idx[m] = idx[2 * m];

	}

	for (size_t m = 0; m < M; m++) {
		idx[M + m] = idx_odd[m];
	}

	recursive_bit_reversal(&idx[0], M);
	recursive_bit_reversal(&idx[M], M);

}

void print_usage_and_exit(char *argv_0) {
	printf(
			"Usage:%s T N\n"
					"\tT type (f32|Q8_7) float 32 or fixed-point Q8.7\n"
					"\tN N power of 2", argv_0);
	exit(1);
}

int main(int argc, char **argv) {

	if (argc <= 2) {
		print_usage_and_exit(argv[0]);
	}

	size_t N;
	if (sscanf(argv[2], "%zu", &N) != 1) {
		print_usage_and_exit(argv[0]);
	}

	if (!is_power_2(N)) {
		print_usage_and_exit(argv[0]);
	}

	if (strcmp(argv[1], "Q8_7") == 0) {
		fft_q8_7_gen(N);
	} else if (strcmp(argv[1], "f32") == 0) {
		fft_f32_gen(N);
	} else {
		print_usage_and_exit(argv[0]);
	}

}
