#ifndef _BN8_MISC
#define _BN8_MISC

#include <openssl/bn.h>
#include <stdio.h>
#include <stdint.h>
#include "bignum8.h"
#include <string.h>

#include "bn8_misc.h"

void bn8_to_bn(BIGNUM *r, const bn8 a)
{
	/*if(a[0] & 0x80)
	{
		bn8_negative(a);
		BN_bin2bn(a, BN8_SIZE, r);
		BN_set_negative(r,1);
	} else		*/
		BN_bin2bn(a, BN8_SIZE, r);
}

void bn8_from_bn(bn8 r, const BIGNUM *a)
{
	int n = BN_num_bytes(a);
	memset(r, 0, BN8_SIZE);
	BN_bn2bin(a, r+1+(BN8_SIZE-1)-n);
	if(BN_is_negative(a))
		bn8_negative(r);
}

void bn8_cmp_bn(bn8 a, uint8_t size, BIGNUM *b, int i)
{
	BIGNUM *aBN = BN_new();
	BN_bin2bn(a, size, aBN);
	if(BN_cmp(aBN, b) != 0) {
		printf("cmp fail %d\n", i);
		BN_print_fp(stdout, aBN); printf("\n");
		BN_print_fp(stdout, b); printf("\n");
	}
}

void bn8_print(const bn8 a)
{
	uint8_t i;
	
	for(i=0; i<BN8_SIZE; i++)
	{
		printf("%02x", a[i]);
	}
}

void bn8_printn(const bn8 a, uint8_t n)
{
	uint8_t i;
	
	for(i=0; i<n; i++)
	{
		printf("%02x", a[i]);
	}
}

#endif