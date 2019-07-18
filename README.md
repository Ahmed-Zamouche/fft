# fft - Fixed point fast fourier transform

This library provide a FFT fixed point implementation using the `libfixmath` library.
# Build

To build, simply type `make`. This will build the example.  
By default, the fixed point implementation is compiled. If you want to use `float` instead type  `make FFT_IMPL=F32`

# todo

* Add the following target:
  - `library` as default target to build  `libfft-q8_7.a` and `libfft-f32.a` for Q8.7 and float implementation respectively
  - `generate` target for generating __twiddle factors__ and __bit reversal__
  - example target for example
* TBD