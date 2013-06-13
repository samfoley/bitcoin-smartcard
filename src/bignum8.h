#ifndef _BIGNUM8_H
#define _BIGNUM8_H

/*
8bit BIGNUM library

operations over 256bit integers

*/

#define BN8_SIZE 33
#define BN8_WORD_SIZE 8

typedef uint8_t* bn8;

// temporary OpenSSL BN functions
void bn8_mod_add(BIGNUM *ret, BIGNUM *a, BIGNUM *b, const BIGNUM *m,
         BN_CTX *ctx);
void bn8_mod_sub(BIGNUM *ret, BIGNUM *a, BIGNUM *b, const BIGNUM *m,
         BN_CTX *ctx);
//void bn8_nnmod(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
void bn8_mod_mul(BIGNUM *ret, BIGNUM *a, BIGNUM *b, const BIGNUM *m,
         BN_CTX *ctx);
		 
// Integer operations
void bn8_to_bn(BIGNUM *r, bn8 a);
void bn8_from_bn(bn8 r, BIGNUM *a);
void bn8_add(bn8 r, bn8 a, bn8 b);
void bn8_add_word(bn8 r, uint8_t a);
void bn8_sub(bn8 r, bn8 a, bn8 b);
void bn8_print(bn8 a);
void bn8_negative(bn8 r);
void bn8_fast_reduction(bn8 r, bn8 a);
void bn8_mul(bn8 r, bn8 a, bn8 b, uint8_t size);
void bn8_lshift(bn8 r, uint8_t n);
void bn8_mul(bn8 r, bn8 x, bn8 y, uint8_t size);

#endif
