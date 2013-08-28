#ifndef _BIGNUM32_H
#define _BIGNUM32_H

/*
32bit BIGNUM library

operations over 256bit integers

*/

#define BN32_SIZE 8
#define BN32_WORD_SIZE 32

typedef uint32_t* bn32;

void bn32_to_bin(uint8_t *r, const bn32 b);
void bn32_from_bin(bn32 *r, uint8_t *b);
		 
// Integer operations
void bn32_add(bn32 r, const bn32 a, const bn32 b);
void bn32_add_n(bn32 r, const bn32 a, uint8_t n);
void bn32_add_n32(bn32 r, const bn32 a, uint8_t n);
void bn32_add_word(bn32 r, uint8_t a);
void bn32_sub(bn32 r, const bn32 a, const bn32 b);
void bn32_sub_n(bn32 r, const bn32 a, uint8_t n);
void bn32_sub_nn(bn32 r, uint8_t size_r, const bn32 a, uint8_t size_a);
void bn32_subc(bn32 r, uint8_t c, const bn32 a);
void bn32_sub_acc(bn32 r, const bn32 a, uint8_t size);
void bn32_sub64(bn32 r, const bn32 a);

void bn32_negative(bn32 r);
void bn32_mod(bn32 r, const bn32 mod, uint8_t size);
void bn32_fast_reduction(bn32 r, const bn32 a);
void bn32_barrett_reduction_p(bn32 r, const bn32 a);
void bn32_barrett_reduction_n(bn32 r, const bn32 a);
void bn32_mul(bn32 r, const bn32 x, const bn32 y, uint8_t sizex, uint8_t sizey);
void bn32_sqr(bn32 r, const bn32 x, uint8_t size);
void bn32_mul3(bn32 r, const bn32 x, uint8_t sizex);
void bn32_lshift(bn32 r, uint8_t n);
void bn32_invert(bn32 r, const bn32 a, const bn32 p);

bn32 bn32_get_p();
bn32 bn32_get_n();


signed char bn32_cmp(const bn32 a, const bn32 b);
signed char bn32_cmp64(const bn32 a, const bn32 b);
signed char bn32_cmp_n(const bn32 a, const bn32 b, uint8_t n);
signed char bn32_cmp_nn(const bn32 a, uint8_t sizea, const bn32 b, uint8_t sizeb);
void bn32_add_shift(bn32 r, const bn32 a, uint8_t n);
void bn32_zero(bn32 r, uint8_t size);
signed char bn32_cmpc(const bn32 a, const uint8_t c, const bn32 b);
void bn32_rshift1(bn32 r, uint8_t size);
void bn32_lshift1(bn32 r, uint8_t size);
void bn32_rshift1_2s(bn32 r, uint8_t size);
uint8_t bn32_is_even(const bn32 a, uint8_t size);
uint8_t bn32_is_one(const bn32 a, uint8_t size);
void bn32_copy(bn32 r, const bn32 a, uint8_t size);
uint8_t bn32_is_bit_set(const bn32 a, uint8_t i);

#endif
