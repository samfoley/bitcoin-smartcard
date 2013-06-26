#ifndef _BIGNUM8_H
#define _BIGNUM8_H

/*
8bit BIGNUM library

operations over 256bit integers

*/

#define BN8_SIZE 32
#define BN8_WORD_SIZE 8

typedef uint8_t* bn8;

		 
// Integer operations
void bn8_add(bn8 r, const bn8 a, const bn8 b);
void bn8_add_n(bn8 r, const bn8 a, uint8_t n);
void bn8_add_n32(bn8 r, const bn8 a, uint8_t n);
void bn8_add_word(bn8 r, uint8_t a);
void bn8_sub(bn8 r, const bn8 a, const bn8 b);
void bn8_sub_n(bn8 r, const bn8 a, uint8_t n);
void bn8_sub_nn(bn8 r, uint8_t size_r, const bn8 a, uint8_t size_a);
void bn8_subc(bn8 r, uint8_t c, const bn8 a);
void bn8_sub_acc(bn8 r, const bn8 a, uint8_t size);
void bn8_sub64(bn8 r, const bn8 a);

void bn8_negative(bn8 r);
void bn8_mod(bn8 r, const bn8 mod, uint8_t size);
void bn8_fast_reduction(bn8 r, const bn8 a);
void bn8_barrett_reduction_p(bn8 r, const bn8 a);
void bn8_barrett_reduction_n(bn8 r, const bn8 a);
void bn8_mul(bn8 r, const bn8 x, const bn8 y, uint8_t sizex, uint8_t sizey);
void bn8_mul3(bn8 r, const bn8 x, uint8_t sizex);
void bn8_lshift(bn8 r, uint8_t n);
void bn8_invert(bn8 r, const bn8 a, const bn8 p);

bn8 bn8_get_p();
bn8 bn8_get_n();


signed char bn8_cmp(const bn8 a, const bn8 b);
signed char bn8_cmp64(const bn8 a, const bn8 b);
signed char bn8_cmp_n(const bn8 a, const bn8 b, uint8_t n);
signed char bn8_cmp_nn(const bn8 a, uint8_t sizea, const bn8 b, uint8_t sizeb);
void bn8_add_shift(bn8 r, const bn8 a, uint8_t n);
void bn8_zero(bn8 r, uint8_t size);
signed char bn8_cmpc(const bn8 a, const uint8_t c, const bn8 b);
void bn8_rshift1(bn8 r, uint8_t size);
void bn8_lshift1(bn8 r, uint8_t size);
void bn8_rshift1_2s(bn8 r, uint8_t size);
uint8_t bn8_is_even(const bn8 a, uint8_t size);
uint8_t bn8_is_one(const bn8 a, uint8_t size);
void bn8_copy(bn8 r, const bn8 a, uint8_t size);
uint8_t bn8_is_bit_set(const bn8 a, uint8_t i);

#endif
