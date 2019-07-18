/*
 * main.c
 *
 *  Created on: 26 Nov 2017
 *      Author: Ahmed.Z
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <math.h>

/**
 * @see http://www.st.com/content/ccc/resource/technical/document/application_note/group0/c1/ee/18/7a/f9/45/45/3b/DM00273990/files/DM00273990.pdf/jcr:content/translations/en.DM00273990.pdf
 */
#include "fft.h"

#if defined(FFT_IMPL_Q8_7)
#ifndef float32_t
#define float32_t float
#endif

float32_t _toFloat32(Q8_7_t a) {
	return (a / (float32_t) (1<<Q8_7_SHIFT));
}

Q8_7_t _fromFloat32(float32_t a) {
	Q8_7_t c;
	float32_t temp = a * (1 << Q8_7_SHIFT);

	if (temp > Q8_7_MAX)		/*saturate the result before assignment*/
		c = Q8_7_MAX;
	else if (temp < Q8_7_MIN)
		c = Q8_7_MIN;
	else
		c = (Q8_7_t)temp;
	return c;
}
#endif

static void Complex_toPolar(Polar_t *p, Complex_t *c)
{
#if defined(FFT_IMPL_F32)
	p->amp 	 = sqrt(pow(c->re,2) + pow(c->im,2));
	p->phase = atan2(c->re, c->im);
#elif defined(FFT_IMPL_Q8_7)
	float32_t c_re, c_im;
	c_re = _toFloat32(c->re);
	c_im = _toFloat32(c->im);
	p->amp 	 = _fromFloat32(sqrt(pow(c_re,2) + pow(c_im,2)));
	p->phase = _fromFloat32(atan2(c_re, c_im));
#endif

}


int main(int argc, char** argv)
{
#if defined(FFT_IMPL_F32)
	float32_t fs = 10.0; /*sample per s*/

	Complex_t X[FFT_X_N];
	for (size_t i = 0; i < FFT_X_N; ++i) {
		X[i].re = sin(i) + cos(0.5*i+PI_F32/3);
		X[i].im = 0;
	}

	fft(X);

	printf("fft=[\n");
	float32_t f = 0.0f;
	for (size_t i = 0; i < (FFT_X_N/2); ++i, f+=(fs/FFT_X_N)) {
		Polar_t p;
		Complex_toPolar(&p, &X[i]);
		printf("%f, %f, %f;\n", f, p.amp, p.phase);
	}
	printf("];\n"
			"figure 1;\n"
			" subplot(2,1,1); plot(fft(:,1), fft(:,2)); grid on;\n"
			" subplot(2,1,2); plot(fft(:,1), fft(:,3)); grid on;\n");
#elif defined(FFT_IMPL_Q8_7)
	float32_t fs = 10.0f; /*sample per s*/

	Complex_t X[FFT_X_N];
	for (size_t i = 0; i < FFT_X_N; ++i) {
		X[i].re = _fromFloat32( sin(i) + cos(0.5*i+3.14/3) );
		X[i].im = 0;
	}

	fft(X);

	printf("fft=[\n");
	float32_t f = 0.0;
	for (size_t i = 0; i < (FFT_X_N/2); ++i, f+=(fs/FFT_X_N)) {
		Polar_t p;
		Complex_toPolar(&p, &X[i]);
		printf("%f, %f, %f;\n", f, _toFloat32(p.amp), _toFloat32(p.phase));
	}
	printf("];\n"
			"figure 1;\n"
			" subplot(2,1,1); plot(fft(:,1), fft(:,2)); grid on;\n"
			" subplot(2,1,2); plot(fft(:,1), fft(:,3)); grid on;\n");
#else
#error "FFT_IMPL possible value FFT_IMPL_F32=0 or FFT_IMPL_FQ8_7=1"
#endif
	return 0;
}

