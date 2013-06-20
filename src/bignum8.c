#include <openssl/bn.h>
#include <stdio.h>
#include <stdint.h>
#include "bignum8.h"
#include <string.h>

uint8_t t1[BN8_SIZE] = { 0 };
uint8_t t2[BN8_SIZE] = { 0 };
uint8_t t3[BN8_SIZE] = { 0 };
uint8_t t4[BN8_SIZE] = { 0 };
uint8_t tr[BN8_SIZE*2] = { 0 };
uint8_t tmul[BN8_SIZE*2] = { 0 };

uint8_t MOD_P[BN8_SIZE] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F};

void bn8_to_bn(BIGNUM *r, bn8 a)
{
	/*if(a[0] & 0x80)
	{
		bn8_negative(a);
		BN_bin2bn(a, BN8_SIZE, r);
		BN_set_negative(r,1);
	} else		*/
		BN_bin2bn(a, BN8_SIZE, r);
}

void bn8_from_bn(bn8 r, BIGNUM *a)
{
	int n = BN_num_bytes(a);
	memset(r, 0, BN8_SIZE);
	BN_bn2bin(a, r+1+(BN8_SIZE-1)-n);
	if(BN_is_negative(a))
		bn8_negative(r);
}

void bn8_negative(bn8 r)
{
	uint8_t i;
	
	for(i=0; i<BN8_SIZE; i++)
			r[i] = ~r[i];
	bn8_add_word(r,1);
}

void bn8_mod_add(BIGNUM *ret, BIGNUM *a, BIGNUM *b, const BIGNUM *m,
         BN_CTX *ctx)
{
	BIGNUM *tmp = BN_new();
	BIGNUM *tmp2 = BN_new();
	
	bn8_from_bn(t1, a);
	bn8_from_bn(t2, b);
	bn8_add(t3, t1, t2);
	bn8_to_bn(ret, t3);
	
	BN_mod_add(tmp, a, b, m, ctx);
	if(BN_cmp(tmp,ret)) {
		printf("\n\nadd error \n");
		bn8_print(t1); printf(" + \n");
		bn8_print(t2); printf("\n");
		BN_print_fp(stdout, a);printf(" + \n");
		BN_print_fp(stdout, b);printf("\nt3=");
		bn8_print(t3); printf("\nbn8=");
		BN_print_fp(stdout, tmp);printf("\n BN=");
		BN_print_fp(stdout, tmp2);printf("\n");
	}
	
	BN_free(tmp);
}

void bn8_mod_sub(BIGNUM *ret, BIGNUM *a, BIGNUM *b, const BIGNUM *m,
         BN_CTX *ctx)
{
	uint8_t i;
	BIGNUM *tmp = BN_new();
	BIGNUM *tmp2 = BN_new();	
	
	bn8_from_bn(t1, a);
	bn8_from_bn(t2, b);
	bn8_sub(t3, t1, t2);
	
	bn8_to_bn(tmp, t3);		
	
	BN_mod_sub(tmp2, a, b, m, ctx);
	
	if(BN_cmp(tmp,tmp2)) {
		printf("\n\nsub error \n");
		bn8_print(t1); printf(" - \n");
		bn8_print(t2); printf("\n");
		BN_print_fp(stdout, a);printf(" - \n");
		BN_print_fp(stdout, b);printf("\nt3=");
		bn8_print(t3); printf("\nbn8=");
		BN_print_fp(stdout, tmp);printf("\nBN=");
		BN_print_fp(stdout, tmp2);printf("\n");
	}
	BN_nnmod(ret, tmp, m, ctx);
	BN_free(tmp);
}

void bn8_mod_mul(BIGNUM *ret, BIGNUM *a, BIGNUM *b, const BIGNUM *m,
         BN_CTX *ctx)
{
	uint8_t i;
	BIGNUM *tmp = BN_new();
	BIGNUM *tmp2 = BN_new();	
	
	bn8_from_bn(t1, a);
	bn8_from_bn(t2, b);
	bn8_mul(tmul, t1, t2, 32);

	bn8_fast_reduction(tr, tmul);
	
	BN_bin2bn(tr, 64, tmp);
	BN_bin2bn(tmul, 64, tmp2);
	
	//BN_mod_mul(ret, a, b, m, ctx);
	//BN_mul(tmp2, a, b, ctx);
	BN_nnmod(ret, tmp2, m, ctx);
	
	if(BN_cmp(ret,tmp)) {
		printf("\n\nmul error \n");
		bn8_print(t1); printf(" * \n");
		bn8_print(t2); printf("\n");
		BN_print_fp(stdout, a);printf(" * \n");
		BN_print_fp(stdout, b);printf("\ntmul=");
		bn8_print(tmul); bn8_print(tmul+BN8_SIZE); printf("\n\nbn8=");
		BN_print_fp(stdout, tmp);printf("\nBN= ");
		BN_print_fp(stdout, ret);printf("\n\n");
	}
	
	BN_free(tmp);
}
/*
void bn8_nnmod(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx)
{
	uint8_t i;
	BIGNUM *tmp = BN_new();
	BIGNUM *tmp2 = BN_new();	
	
	bn8_from_bn(t1, a);	
	bn8_from_bn(t2, m);	
	
	bn8_fast_reduction(t3, t1);
	
	bn8_to_bn(tmp, t3);		
	
	BN_nnmod(r, a, m, ctx);
	
	if(BN_cmp(tmp,r)) {
		printf("\n\nnnmod error \n");
		bn8_print(t1); printf(" - \n");
		bn8_print(t2); printf("\n");
		BN_print_fp(stdout, a);printf(" - \n");
		BN_print_fp(stdout, b);printf("\nt3=");
		bn8_print(t3); printf("\nbn8=");
		BN_print_fp(stdout, tmp);printf("\nBN=");
		BN_print_fp(stdout, tmp2);printf("\n");
	}	
	BN_free(tmp);
}*/

void bn8_add(bn8 r, const bn8 a, const bn8 b)
{
	int i;
	uint8_t carry;
	uint16_t sum;
	
	sum = a[BN8_SIZE-1]+b[BN8_SIZE-1];
	carry = (sum&0xff00) ? 1:0;
	r[BN8_SIZE-1] = sum&0xff;
	
	for(i=BN8_SIZE-2; i>=0; i--)
	{
		sum = a[i]+b[i]+carry;
		carry = (sum&0xff00) ? 1:0;
		r[i] = sum&0xff;
	}		
	if(i = bn8_cmpc(r, carry, MOD_P) > 0)	
	{
		bn8_subc(r, carry, MOD_P);
	}
	
}

void bn8_addc(bn8 r, const bn8 a)
{
	int i;
	uint8_t carry;
	uint16_t sum;
	
	sum = r[BN8_SIZE-1]+a[BN8_SIZE-1];
	carry = (sum&0xff00) ? 1:0;
	r[BN8_SIZE-1] = sum&0xff;
	
	for(i=BN8_SIZE-2; i>=0; i--)
	{
		sum = r[i]+a[i]+carry;
		carry = (sum&0xff00) ? 1:0;
		r[i] = sum&0xff;
	}
} 

void bn8_add_word(bn8 r, uint8_t a)
{
	int i;
	uint8_t carry;
	uint16_t sum;
	
	sum = r[BN8_SIZE-1]+a;
	carry = (sum&0xff00) ? 1:0;
	r[BN8_SIZE-1] = sum&0xff;
	
	for(i=BN8_SIZE-2; i>=0; i--)
	{
		sum = r[i]+carry;
		carry = (sum&0xff00) ? 1:0;
		r[i] = sum&0xff;
		if(!carry) return;
	}	
	
	if(bn8_cmpc(r, carry, MOD_P) > 0)
		bn8_subc(r, carry, MOD_P);
	//r[i] = carry;
}

void bn8_sub(bn8 r, const bn8 a, const bn8 b)
{
	int i;
	uint8_t carry;
	uint16_t sum;
	
	sum = a[BN8_SIZE-1]-b[BN8_SIZE-1];
	carry = (sum&0xff00) ? 1:0;
	r[BN8_SIZE-1] = sum&0xff;
	
	for(i=BN8_SIZE-2; i>=0; i--)
	{
		sum = a[i]-b[i]-carry;
		carry = (sum&0xff00) ? 1:0;
		r[i] = sum&0xff;
	}	
	if(carry) bn8_addc(r, MOD_P);
}

void bn8_subc(bn8 r, uint8_t c, const bn8 a)
{
	int i;
	uint8_t carry;
	uint16_t sum;
	
	sum = r[BN8_SIZE-1]-a[BN8_SIZE-1];
	carry = (sum&0xff00) ? 1:0;
	r[BN8_SIZE-1] = sum&0xff;
	
	for(i=BN8_SIZE-2; i>=0; i--)
	{
		sum = r[i]-a[i]-carry;
		carry = (sum&0xff00) ? 1:0;
		r[i] = sum&0xff;
	}	
}

void bn8_sub64(bn8 r, bn8 a)
{
	int i;
	uint8_t carry;
	uint16_t sum;
	
	sum = r[2*BN8_SIZE-1]-a[BN8_SIZE-1];
	carry = (sum&0xff00) ? 1:0;
	r[2*BN8_SIZE-1] = sum&0xff;
	
	for(i=BN8_SIZE-2; i>=0; i--)
	{
		sum = r[i+BN8_SIZE]-a[i]-carry;
		carry = (sum&0xff00) ? 1:0;
		r[i+BN8_SIZE] = sum&0xff;
	}	
	for(i=BN8_SIZE-1; i>=0; i--)
	{
		sum = r[i]-carry;
		carry = (sum&0xff00) ? 1:0;
		r[i] = sum&0xff;
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

void bn8_zero(bn8 r, uint8_t size)
{
	while(size)
	{
		*r = 0;
		r++;
		size--;
	}
}

// reduces c based on septk1256
// c and r 64 byte
void bn8_fast_reduction(bn8 r, bn8 c)
{
	BIGNUM *rBN = BN_new();
	BIGNUM *a0BN = BN_new();
	BIGNUM *a1BN = BN_new();
	BIGNUM *c0BN = BN_new();
	BIGNUM *axBN = BN_new();
	BIGNUM *pBN = BN_new();
	BIGNUM *tmpBN = BN_new();
	
	uint8_t a[BN8_SIZE*2] = {0};
	bn8 a0,a1;
	bn8 c1 = c;
	bn8 c0 = c + BN8_SIZE;
	
	bn8_zero(a, BN8_SIZE*2);		
		
	bn8_add_shift(a, c1, 32);	
	bn8_add_shift(a, c1, 9);
	bn8_add_shift(a, c1, 8);
	bn8_add_shift(a, c1, 7);
	bn8_add_shift(a, c1, 6);
	bn8_add_shift(a, c1, 4);
	bn8_add_shift(a, c1, 0);
	
	
	
	
	a1 = a;
	a0 = a+BN8_SIZE;
	
	BN_bin2bn(a1, 32, a1BN);
	BN_bin2bn(a0, 32, a0BN);
	BN_bin2bn(c0, 32, c0BN);
	BN_bin2bn(MOD_P, 32, pBN);
	
	BN_zero(rBN);
	BN_add(rBN, rBN, a1BN);
	BN_add(rBN, rBN, a0BN);
	BN_add(rBN, rBN, c0BN);
	
	BN_lshift(axBN, a1BN, 32);
	BN_add(rBN, rBN, axBN);
	BN_lshift(axBN, a1BN, 9);
	BN_add(rBN, rBN, axBN);
	BN_lshift(axBN, a1BN, 8);
	BN_add(rBN, rBN, axBN);
	BN_lshift(axBN, a1BN, 7);
	BN_add(rBN, rBN, axBN);
	BN_lshift(axBN, a1BN, 6);
	BN_add(rBN, rBN, axBN);
	BN_lshift(axBN, a1BN, 4);
	BN_add(rBN, rBN, axBN);
	
	bn8_zero(r, BN8_SIZE*2);
	bn8_add_shift(r, a1, 32);
	bn8_add_shift(r, a1, 9);
	bn8_add_shift(r, a1, 8);
	bn8_add_shift(r, a1, 7);
	bn8_add_shift(r, a1, 6);
	bn8_add_shift(r, a1, 4);
	bn8_add_shift(r, a1, 0);
	bn8_add_shift(r, a0, 0);
	bn8_add_shift(r, c0, 0);
	
	
	
	printf("\nbn ");
	bn8_print(r);bn8_print(r+BN8_SIZE);
	printf("\nBN ");
	BN_print_fp(stdout, rBN);
	printf("\n\n");
	
	while(BN_cmp(rBN, pBN) > 0)
	{
		BN_sub(tmpBN, rBN, pBN);
		BN_copy(rBN, tmpBN);
	}
	
	bn8_zero(r, BN8_SIZE*2);
	bn8_from_bn(r+BN8_SIZE, rBN);
	return;
	
	while(bn8_cmp64(r, MOD_P) > 0)
		bn8_sub64(r, MOD_P);	
	
}

// r += a << n
// r: 64 bytes
// a: 32 bytes
void bn8_add_shift(bn8 r, bn8 a, uint8_t n)
{
	uint8_t t;
	uint8_t offset = n/BN8_WORD_SIZE;
	n %= BN8_WORD_SIZE;
	
	int i;
	uint8_t carry;
	uint16_t sum;
	
	t = (a[BN8_SIZE-1]<<n);
	sum = r[BN8_SIZE*2-1-offset]+t;
	carry = (sum&0xff00) ? 1:0;
	r[BN8_SIZE*2-1-offset] = sum&0xff;
	
	
	for(i=BN8_SIZE-2; i>=0; i--)
	{				
		sum = r[i+BN8_SIZE-offset]+carry;
		carry = a[i+1]>>(BN8_WORD_SIZE-n);
		t = a[i]<<n | carry;
		sum += t;
		carry = (sum&0xff00) ? 1:0;
		r[i+BN8_SIZE-offset] = sum&0xff;
	}	
	for(i=BN8_SIZE-offset-1; i; i--)
	{
		sum = r[i]+carry;
		carry = (sum&0xff00) ? 1:0;
		r[i] = sum&0xff;
	}
	r[i] += carry;	
}

void bn8_lshift(bn8 r, uint8_t n)
{
	uint8_t i;
	uint8_t carry;
	uint8_t offset = n/BN8_WORD_SIZE;
	n %= BN8_WORD_SIZE;
	if(offset)
	{
		for(i=0; i<(BN8_SIZE-offset); i++)
		{
			r[i] = r[i+offset];
		}
		for(; i<BN8_SIZE; i++)
		{
			r[i] = 0;
		}
	}
		
	for(i=0; i<BN8_SIZE; i++)
	{
		carry = (i+1==BN8_SIZE) ? r[i+1]>>(BN8_WORD_SIZE-n) : 0;
		r[i] = r[i]<<n | carry;
	}
}

void bn8_mul(bn8 r, bn8 x, bn8 y, uint8_t size)
{
	int i,j;	
	uint16_t uv=0;
	
	
	for(i=0; i<2*size; i++)
		r[i]=0;
		
	for(i=size-1; i>=0; i--)
	{
		uv &= 0xff;
		
		for(j=size-1; j>=0; j--)
		{
			uv = r[i+j+1]+x[i]*y[j] + ((uv>>8) & 0xff);
			r[i+j+1]=uv&0xff;
		}
		r[i]=((uv>>8) &0xff);
	}
}
/*
void bn8_mul(bn8 r, bn8 x, bn8 y, uint8_t size)
{
	if(size==1)
	{
		*r = *x * *y;
	}
	else
	{
		uint_8 l = size/2;
		bn8 x0,x1,y0,y1;
		x0 = x+l;
		x1 = x;
		y0 = y+l;
		y1 = y;
		
		bn8_mul(x1y1, x1, y1, l);
		bn8_add(t1, x0, x1);
		bn8_add(t2, y0, y1);
		bn8_mul(t1t2, t1, t2, l);
		bn8_mul(x0y0, x0, y0, l);
		
		bn8_add(t3, x1y1, x0y0);
		bn8_sub(t4, t1t2, t3);
		bn8_lshift(t4, l);
		bn8_lshift(x1y1, 2*l);
		bn8_add(t5, x1y1, t4);
		bn8_add(r, t5, x0y0);
	}
}*/

signed char bn8_cmp64(const bn8 a, const bn8 b)
{
	char i;	
	for(i=0; i<BN8_SIZE; i++)
	{
		if(a[i]) return 1;
	}
	for(i=0; i<BN8_SIZE; i++)
	{
		if(a[i+BN8_SIZE]>b[i]) return 1;
		if(a[i+BN8_SIZE]<b[i]) return -1;		
	}
	return 0;
}

signed char bn8_cmp(const bn8 a, const bn8 b)
{
	char i;	
	for(i=0; i<BN8_SIZE; i++)
	{
		if(a[i]>b[i]) return 1;
		if(a[i]<b[i]) return -1;		
	}
	return 0;
}

signed char bn8_cmpc(const bn8 a, const uint8_t c, const bn8 b)
{
	char i;
	
	if(c)
	{
		return (c>>7) ? -1:1;
	}
	for(i=0; i<BN8_SIZE; i++)
	{
		if(a[i]>b[i]) return 1;
		if(a[i]<b[i]) return -1;		
	}
	return 0;
}