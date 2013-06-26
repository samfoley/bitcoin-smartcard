#ifndef _BN8_MISC_H
#define _BN8_MISC_H

void bn8_to_bn(BIGNUM *r, const bn8 a);
void bn8_from_bn(bn8 r, const BIGNUM *a);
void bn8_cmp_bn(bn8 a, uint8_t size, BIGNUM *b, int message);

void bn8_print(const bn8 a);
void bn8_printn(const bn8 a, uint8_t n);

#endif