/*
 * fft.h
 *
 *  Created on: 27 Nov 2017
 *      Author: Ahmed.Z
 */

#ifndef INC_FFT_GEN_H_
#define INC_FFT_GEN_H_
#include <stdbool.h>
#include <stddef.h>

extern const float PI;

bool is_power_2 (size_t N);
size_t log_2(size_t N);

void bit_reversal_type(const char *type, size_t N);
void recursive_bit_reversal(size_t *idx, size_t N);

void fft_q8_7_gen(size_t N);
void fft_f32_gen(size_t N);

#endif /* INC_FFT_GEN_H_ */
