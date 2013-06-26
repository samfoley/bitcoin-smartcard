#include <stdint.h>
#include "bignum8.h"


uint8_t t1[BN8_SIZE] = { 0 };
uint8_t t2[BN8_SIZE] = { 0 };
uint8_t t3[BN8_SIZE] = { 0 };
uint8_t t4[BN8_SIZE] = { 0 };
uint8_t tr[BN8_SIZE+2] = { 0 };
uint8_t tmul[BN8_SIZE*2] = { 0 };

uint8_t MOD_0000P[BN8_SIZE+4] = {0x00, 0x00, 0x00, 0x00, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F};

uint8_t MOD_0000N[BN8_SIZE+4] = {0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

uint8_t U0_P[10] = {0x01, 0x00, 0x00, 0x03, 0xd1};
uint8_t U0_N[17] = {0x01, 0x45, 0x51, 0x23, 0x19, 0x50, 0xb7, 0x5f, 0xc4, 0x40, 0x2d, 0xa1, 0x73, 0x2f, 0xc9, 0xbe, 0xc0};

#define MOD_P (MOD_0000P+4)
#define MOD_N (MOD_0000N+4)



void bn8_negative(bn8 r)
{
	uint8_t i;
	
	for(i=0; i<BN8_SIZE; i++)
			r[i] = ~r[i];
	bn8_add_word(r,1);
}

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

// r = r+a
// where r is n bytes 
//       a is n-1 bytes
void bn8_add_n(bn8 r, const bn8 a, uint8_t n)
{
	int i;
	uint8_t carry;
	uint16_t sum;
	
	sum = r[n-1]+a[n-2];
	carry = (sum&0xff00) ? 1:0;
	r[n-1] = sum&0xff;
	
	for(i=n-2; i>0; i--)
	{
		sum = r[i]+a[i-1]+carry;
		carry = (sum&0xff00) ? 1:0;
		r[i] = sum&0xff;
	}
	r[0] = r[0]+carry;
}

void bn8_add_n32(bn8 r, const bn8 a, uint8_t n)
{
	int i;
	uint8_t carry;
	uint16_t sum;
	
	sum = r[n-1]+a[BN8_SIZE-1];
	carry = (sum&0xff00) ? 1:0;
	r[n-1] = sum&0xff;
	
	for(i=2; i<=BN8_SIZE; i++)
	{
		sum = r[n-i]+a[BN8_SIZE-i]+carry;
		carry = (sum&0xff00) ? 1:0;
		r[n-i] = sum&0xff;
	}
	for(; i<n; i++)
	{
		sum = r[n-i]+carry;
		carry = (sum&0xff00) ? 1:0;
		r[n-i] = sum&0xff;
	}
	r[0] = r[0]+carry;	
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

void bn8_sub_acc(bn8 r, const bn8 a, uint8_t size)
{
	int i;
	uint8_t carry, carry1;
	uint16_t sum;	
	
	sum = r[size-1]-a[size-1];
	carry = (sum&0xff00) ? 1:0;
	r[size-1] = sum&0xff;
	
	for(i=size-2; i>=0; i--)
	{
		sum = r[i]-a[i]-carry;
		carry1 = carry;
		carry = (sum&0xff00) ? 1:0;
		r[i] = sum&0xff;
	}	
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

// r = r-a
// where r is n bytes
//       a is n-1 bytes
// (assumes: result always positive)
void bn8_sub_n(bn8 r, const bn8 a, uint8_t n)
{
	int i;
	uint8_t carry;
	uint16_t sum;	
	
	sum = r[n-1]-a[n-2];
	carry = (sum&0xff00) ? 1:0;
	r[n-1] = sum&0xff;
	
	for(i=n-2; i>0; i--)
	{
		sum = r[i]-a[i-1]-carry;
		carry = (sum&0xff00) ? 1:0;
		r[i] = sum&0xff;
	}	
	r[0] = r[0] - carry;	
}

void bn8_sub64(bn8 r, const bn8 a)
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

// r = r - a
// r is size_r bytes
// a is size_a bytes
// size_a <= size_r
void bn8_sub_nn(bn8 r, uint8_t size_r, const bn8 a, uint8_t size_a)
{
	int i;
	uint8_t carry;
	uint16_t sum;
	
	sum = r[size_r-1]-a[size_a-1];
	carry = (sum&0xff00) ? 1:0;
	r[size_r-1] = sum&0xff;
	
	for(i=size_a-2; i>=0; i--)
	{
		sum = r[i+size_r-size_a]-a[i]-carry;
		carry = (sum&0xff00) ? 1:0;
		r[i+size_r-size_a] = sum&0xff;
	}	
	if(size_r-size_a)
	{
		for(i=size_r-size_a-1; i>=0; i--)
		{
			sum = r[i]-carry;
			carry = (sum&0xff00) ? 1:0;
			r[i] = sum&0xff;
		}
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

// r = r % mod
// mod 32 bytes
// r size bytes
void bn8_mod(bn8 r, const bn8 mod, uint8_t size)
{
	while(bn8_cmp_nn(r, size, mod, BN8_SIZE) > 0)
		bn8_sub_nn(r, size, mod, BN8_SIZE);	
}

// reduces c based on septk1256
// c and r 64 byte
void bn8_fast_reduction(bn8 r, const bn8 c)
{
	uint8_t a[BN8_SIZE*2] = {0};
	bn8 a0,a1;
	bn8 c1 = c;
	bn8 c0 = c + BN8_SIZE;
	
	while(bn8_cmp(c1, MOD_P) > 0)
		bn8_subc(c1, 0, MOD_P);	
		
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
		
	bn8_zero(r, BN8_SIZE*2);		
	
	while(bn8_cmp_nn(r, BN8_SIZE*2, MOD_P, BN8_SIZE) > 0)
		bn8_sub_nn(r, BN8_SIZE*2, MOD_P, BN8_SIZE);	
	
}

void bn8_barrett_reduction_p(bn8 r, const bn8 z)
{
	uint8_t i;
	uint8_t q_[BN8_SIZE+1] = {0}; // 33 byte
	uint8_t q_p[BN8_SIZE*2+1] = {0};
	bn8_zero(r, BN8_SIZE+2);
	
	bn8_mul(q_p, z, U0_P, BN8_SIZE+1, 5);
	
	
	for(i=0; i<5; i++)
		q_[BN8_SIZE-i] = q_p[4-i];
	bn8_add_n(q_, z, BN8_SIZE+1);	
	
	
	bn8_mul(q_p, q_, MOD_P, BN8_SIZE+1, BN8_SIZE); // todo: efficient 33 byte multiplication
	
	if(bn8_cmp_n(z+BN8_SIZE-1, q_p+BN8_SIZE, BN8_SIZE+1) < 0)	
		r[0] = 1;	// Adds b^(k+1) if r would be negative
	
	for(i=0; i<BN8_SIZE+1; i++)	
		r[1+i] = z[31+i];
		
	bn8_sub_n(r, q_p+BN8_SIZE, BN8_SIZE+2);
	
	while(bn8_cmp_nn(r, BN8_SIZE+2, MOD_P, BN8_SIZE) > 0)
	{
		bn8_sub_nn(r, BN8_SIZE+2, MOD_P, BN8_SIZE);
	}
}

void bn8_barrett_reduction_n(bn8 r, const bn8 z)
{
	uint8_t i;
	uint8_t q_[BN8_SIZE+1] = {0}; // 33 byte
	uint8_t q_p[BN8_SIZE*2+1] = {0};
	bn8_zero(r, BN8_SIZE+2);
	
	bn8_mul(q_p, z, U0_N, BN8_SIZE+1, 17);
	
	
	for(i=0; i<17; i++)
		q_[BN8_SIZE-i] = q_p[16-i];
	bn8_add_n(q_, z, BN8_SIZE+1);	
	
	
	bn8_mul(q_p, q_, MOD_0000N+4, BN8_SIZE+1, BN8_SIZE); // todo: efficient 33 byte multiplication
	
	if(bn8_cmp_n(z+BN8_SIZE-1, q_p+BN8_SIZE, BN8_SIZE+1) < 0)	
		r[0] = 1;	// Adds b^(k+1) if r would be negative
	
	for(i=0; i<BN8_SIZE+1; i++)	
		r[1+i] = z[31+i];
		
	bn8_sub_n(r, q_p+BN8_SIZE, BN8_SIZE+2);
	
	while(bn8_cmp_nn(r, BN8_SIZE+2, MOD_N, BN8_SIZE) > 0)
	{
		bn8_sub_nn(r, BN8_SIZE+2, MOD_N, BN8_SIZE);
	}
}

// r += a << n
// r: 64 bytes
// a: 32 bytes
void bn8_add_shift(bn8 r, const bn8 a, uint8_t n)
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

void bn8_rshift1(bn8 r, uint8_t size)
{
	uint8_t i;
	uint8_t carry;		
		
	for(i=size; i>1; i--)
	{
		carry = r[i-2]<<7;
		r[i-1] = r[i-1]>>1 | carry;
	}
	r[0] = r[0]>>1;
}

void bn8_lshift1(bn8 r, uint8_t size)
{
	uint8_t i;
	uint8_t carry;		
		
	for(i=0; i<size-1; i++)
	{
		carry = r[i+1]>>7;
		r[i] = r[i]<<1 | carry;
	}
	r[size-1] = r[size-1] << 1;
}

void bn8_rshift1_2s(bn8 r, uint8_t size)
{
	uint8_t i;
	uint8_t carry;		
		
	for(i=size; i>1; i--)
	{
		carry = r[i-2]<<7;
		r[i-1] = r[i-1]>>1 | carry;
	}
	if(r[0]&0x80)
		r[0] = (r[0]>>1) | 0x80;
	else
		r[0] = r[0]>>1;
}	

void bn8_mul(bn8 r, const bn8 x, const bn8 y, uint8_t sizex, uint8_t sizey)
{
	int i,j;	
	uint16_t uv=0;
	
	
	for(i=0; i<sizex+sizey; i++)
		r[i]=0;
		
	for(i=sizex-1; i>=0; i--)
	{
		uv &= 0xff;
		
		for(j=sizey-1; j>=0; j--)
		{
			uv = r[i+j+1]+x[i]*y[j] + ((uv>>8) & 0xff);
			r[i+j+1]=uv&0xff;
		}
		r[i]=((uv>>8) &0xff);
	}
}

// r = 3x
// r is sizex+1 bytes
void bn8_mul3(bn8 r, const bn8 x, uint8_t sizex)
{
	r[0] = 0;
	bn8_copy(r+1, x, sizex);
	bn8_lshift1(r, sizex+1);
	bn8_add_n(r, x, sizex+1);
}


uint8_t bn8_is_even_2s(bn8 a, uint8_t size)
{
	if(a[0] & 0x80) return (a[size-1] & 0x01);
	return !(a[size-1] & 0x01);
}

uint8_t bn8_is_even(bn8 a, uint8_t size)
{
	return !(a[size-1] & 0x01);
}

uint8_t bn8_is_one(bn8 a, uint8_t size)
{
	uint8_t i = 0;
	
	for(i=0; i<size-1; i++)
	{
		if(a[i]) return 0;
	}
	return a[size-1]==1;
}

void bn8_copy(bn8 r, const bn8 a, uint8_t size)
{
	uint8_t i;
	
	for(i=0; i<size; i++)
		r[i] = a[i];
}

#define X_SIZE (BN8_SIZE*2)

void bn8_invert(bn8 r, const bn8 a, const bn8 p)
{
	uint8_t u[BN8_SIZE];
	uint8_t v[BN8_SIZE];
	uint8_t x1[X_SIZE] = {0};
	uint8_t x2[X_SIZE] = {0};
	
	bn8_copy(u, a, BN8_SIZE);
	bn8_copy(v, p, BN8_SIZE);
	x1[BN8_SIZE*2-1] = 1;
	x2[BN8_SIZE*2-1] = 0;
	
	while(!bn8_is_one(u, BN8_SIZE) && !bn8_is_one(v, BN8_SIZE))
	{
		while(bn8_is_even(u, BN8_SIZE))
		{
			bn8_rshift1(u, BN8_SIZE);
			if(bn8_is_even(x1, X_SIZE))
			{
				bn8_rshift1_2s(x1, X_SIZE);
			} else {
				bn8_add_n32(x1, p, X_SIZE);
				bn8_rshift1_2s(x1, X_SIZE);
			}
		}
		while(bn8_is_even(v, BN8_SIZE))
		{
			bn8_rshift1(v, BN8_SIZE);
			if(bn8_is_even(x2, X_SIZE))
			{
				bn8_rshift1_2s(x2, X_SIZE);
			} else {
				bn8_add_n32(x2, p, X_SIZE);
				bn8_rshift1_2s(x2, X_SIZE);
			}
		}
		if(bn8_cmp(u, v) >= 0)
		{
			bn8_sub_acc(u, v, BN8_SIZE);			
			bn8_sub_acc(x1, x2, X_SIZE);
		} else {
			bn8_sub_acc(v, u, BN8_SIZE);
			bn8_sub_acc(x2, x1, X_SIZE);			
		}
	}
	
	if(bn8_is_one(u, BN8_SIZE))
	{
		if(x1[0] & 0x80) bn8_add_n32(x1, p, X_SIZE);
		while(bn8_cmp64(x1, MOD_P) > 0)
			bn8_sub64(x1, MOD_P);	
		bn8_copy(r+2, x1+BN8_SIZE, BN8_SIZE);		
	} else {
		if(x2[0] & 0x80) bn8_add_n32(x2, p, X_SIZE);
		while(bn8_cmp64(x2, MOD_P) > 0)
			bn8_sub64(x2, MOD_P);	
		bn8_copy(r+2, x2+BN8_SIZE, BN8_SIZE);		
	}	
}

signed char bn8_cmp_n(const bn8 a, const bn8 b, uint8_t n)
{
	uint8_t i;
	
	for(i=0; i<n; i++)
	{
		if(a[i]>b[i]) return 1;
		if(a[i]<b[i]) return -1;		
	}
	return 0;
}

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

// compares a and b
// a > b   = 1
// a == b  = 0
// a < b   = -1
// requires sizeb <= sizea
signed char bn8_cmp_nn(const bn8 a, uint8_t sizea, const bn8 b, uint8_t sizeb)
{
	char i;	
	for(i=0; i<sizea-sizeb; i++)
	{
		if(a[i]) return 1;
	}
	for(i=0; i<sizeb; i++)
	{
		if(a[i+sizea-sizeb]>b[i]) return 1;
		if(a[i+sizea-sizeb]<b[i]) return -1;		
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

bn8 bn8_get_p()
{
	return MOD_P;
}

bn8 bn8_get_n()
{
	return MOD_N;
}



uint8_t bn8_is_bit_set(const bn8 a, uint8_t i)
{
	uint8_t a_i = a[BN8_SIZE-i/BN8_WORD_SIZE-1];
	return (a_i >> (i%BN8_WORD_SIZE)) & 0x01;
}
