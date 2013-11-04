#include "asf.h"
#include "bignum32.h"


uint8_t t1[BN32_SIZE] = { 0 };
uint8_t t2[BN32_SIZE] = { 0 };
uint8_t t3[BN32_SIZE] = { 0 };
uint8_t t4[BN32_SIZE] = { 0 };
uint8_t tr[BN32_SIZE+2] = { 0 };
uint8_t tmul[BN32_SIZE*2] = { 0 };

uint32_t MOD_0000P[BN32_SIZE+4] = {0x00000000, 0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFE,0xFFFFFC2F};

uint32_t MOD_0000N[BN32_SIZE+4] = {0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xBAAEDCE6, 0xAF48A03B, 0xBFD25E8C, 0xD0364141};

uint32_t U0_P[2] = {0x01, 0x000003d1};
uint32_t U0_N[5] = {0x01, 0x45512319, 0x50b75fc4, 0x402da173, 0x2fc9bec0};


#define MOD_P (MOD_0000P+1)
#define MOD_N (MOD_0000N+1)

// Test functions

void bn32_printn(const uint32_t* a, int n)
{
//	uint8_t i;
	
	/*for(i=0; i<n; i++)
	{
		printf("%08x", a[i]);
	}*/
}
void bn32_print(const uint32_t* a){ bn32_printn(a,8); }


// converts bn32 to network ordered byte stream
void bn32_to_bin(uint8_t *r, const bn32 b)
{
	int i;	
	for(i=0; i<BN32_SIZE; i++)
	{
		r[i*4 + 0] = (b[i] & 0xff000000) >> 24;
		r[i*4 + 1] = (b[i] & 0x00ff0000) >> 16;
		r[i*4 + 2] = (b[i] & 0x0000ff00) >> 8;
		r[i*4 + 3] = (b[i] & 0x000000ff) >> 0;
	}
}

// converts network ordered byte stream to bn32
void bn32_from_bin(bn32 r, uint8_t *b)
{
	int i;	
	for(i=0; i<BN32_SIZE; i++)
	{
		r[i] = b[i*4 + 0] << 24;
		r[i] += b[i*4 + 1] << 16;
		r[i] += b[i*4 + 2] << 8;
		r[i] += b[i*4 + 3] << 0;
	}
}


void bn32_negative(bn32 r)
{
	uint8_t i;
	
	for(i=0; i<BN32_SIZE; i++)
			r[i] = ~r[i];
	bn32_add_word(r,1);
}

void bn32_add(bn32 r, const bn32 a, const bn32 b)
{
	int i;
	uint32_t carry;
	uint64_t sum;
	
	sum = (uint64_t) a[BN32_SIZE-1]+b[BN32_SIZE-1];
	carry = sum>>BN32_WORD_SIZE;
	r[BN32_SIZE-1] = sum&0xffffffff;
	
	for(i=BN32_SIZE-2; i>=0; i--)
	{
		sum = (uint64_t) a[i]+b[i]+carry;
		carry = sum>>BN32_WORD_SIZE;		
		r[i] = sum&0xffffffff;
	}		
	if(bn32_cmpc(r, carry, MOD_P) > 0)	
	{
		bn32_subc(r, carry, MOD_P);
	}
	
}

void bn32_addc(bn32 r, const bn32 a)
{
	int i;
	uint32_t carry;
	uint64_t sum;
	
	sum = (uint64_t) r[BN32_SIZE-1]+a[BN32_SIZE-1];
	carry = sum>>BN32_WORD_SIZE;
	r[BN32_SIZE-1] = sum&BN32_MAX;
	
	for(i=BN32_SIZE-2; i>=0; i--)
	{
		sum = (uint64_t) r[i]+a[i]+carry;
		carry = sum>>BN32_WORD_SIZE;
		r[i] = sum&BN32_MAX;
	}
} 

void bn32_add_word(bn32 r, uint8_t a)
{
	int i;
	uint32_t carry;
	uint64_t sum;
	
	sum = (uint64_t) r[BN32_SIZE-1]+a;
	carry = sum>>BN32_WORD_SIZE;
	r[BN32_SIZE-1] = sum&BN32_MAX;
	
	for(i=BN32_SIZE-2; i>=0; i--)
	{
		sum = (uint64_t) r[i]+carry;
		carry = sum>>BN32_WORD_SIZE;
		r[i] = sum&BN32_MAX;
		if(!carry) return;
	}	
	
	if(bn32_cmpc(r, carry, MOD_P) > 0)
		bn32_subc(r, carry, MOD_P);
	//r[i] = carry;
}

// r = r+a
// where r is n bytes 
//       a is n-1 bytes
void bn32_add_n(bn32 r, const bn32 a, uint8_t n)
{
	int i;
	uint32_t carry;
	uint64_t sum;
	
	sum = (uint64_t) r[n-1]+a[n-2];
	carry = sum>>BN32_WORD_SIZE;
	r[n-1] = sum&BN32_MAX;
	
	for(i=n-2; i>0; i--)
	{
		sum = (uint64_t) r[i]+a[i-1]+carry;
		carry = sum>>BN32_WORD_SIZE;
		r[i] = sum&BN32_MAX;
	}
	r[0] = r[0]+carry;
}

// r += a
// where a is 32 bytes
//       r is n bytes with n>32
void bn32_add_n32(bn32 r, const bn32 a, uint8_t n)
{
	int i;
	uint32_t carry;
	uint64_t sum;
	
	sum = (uint64_t) r[n-1]+a[BN32_SIZE-1];
	carry = (sum >> BN32_WORD_SIZE) ? 1:0;
	r[n-1] = sum&BN32_MAX;
	
	for(i=2; i<=BN32_SIZE; i++)
	{
		sum = (uint64_t) r[n-i]+a[BN32_SIZE-i]+carry;
		carry = (sum >> BN32_WORD_SIZE) ? 1:0;
		r[n-i] = sum&BN32_MAX;
	}
	for(; i<n; i++)
	{
		sum = (uint64_t) r[n-i]+carry;
		carry = (sum >> BN32_WORD_SIZE) ? 1:0;
		r[n-i] = sum&BN32_MAX;
	}
	r[0] = r[0]+carry;	
}

void bn32_sub(bn32 r, const bn32 a, const bn32 b)
{
	int i;
	uint32_t carry;
	uint64_t sum;
	
	sum = (uint64_t) a[BN32_SIZE-1]-b[BN32_SIZE-1];
	carry = (sum >> BN32_WORD_SIZE) ? 1:0;
	
	r[BN32_SIZE-1] = sum&BN32_MAX;
	
	for(i=BN32_SIZE-2; i>=0; i--)
	{
		sum = (uint64_t) a[i]-b[i]-carry;
		carry = (sum >> BN32_WORD_SIZE) ? 1:0;
		r[i] = sum&BN32_MAX;
	}	
	if(carry) bn32_addc(r, MOD_P);
}

// r -= a
// where r,a is size
//       
void bn32_sub_acc(bn32 r, const bn32 a, uint8_t size)
{
	int i;
	uint32_t carry;
	uint64_t sum;	
	
	sum = (uint64_t) r[size-1]-a[size-1];
	carry = (sum >> BN32_WORD_SIZE) ? 1:0;
	r[size-1] = sum&BN32_MAX;
	
	for(i=size-2; i>=0; i--)
	{
		sum = (uint64_t) r[i]-a[i]-carry;		
		carry = (sum >> BN32_WORD_SIZE) ? 1:0;
		r[i] = sum&BN32_MAX;
	}	
}

void bn32_subc(bn32 r, uint8_t c, const bn32 a)
{
	int i;
	uint32_t carry;
	uint64_t sum;
	
	sum = (uint64_t) r[BN32_SIZE-1]-a[BN32_SIZE-1];
	carry = (sum >> BN32_WORD_SIZE) ? 1:0;
	r[BN32_SIZE-1] = sum&BN32_MAX;
	
	for(i=BN32_SIZE-2; i>=0; i--)
	{
		sum = (uint64_t) r[i]-a[i]-carry;		
		carry = (sum >> BN32_WORD_SIZE) ? 1:0;		
		r[i] = sum & BN32_MAX;
	}	
}

// r = r-a
// where r is n bytes
//       a is n-1 bytes
// (assumes: result always positive)
void bn32_sub_n(bn32 r, const bn32 a, uint8_t n)
{
	int i;
	uint32_t carry;
	uint64_t sum;	
	
	sum = (uint64_t) r[n-1]-a[n-2];
	carry = (sum >> BN32_WORD_SIZE) ? 1:0;
	r[n-1] = sum&BN32_MAX;
	
	for(i=n-2; i>0; i--)
	{
		sum = (uint64_t) r[i]-a[i-1]-carry;
		carry = (sum >> BN32_WORD_SIZE) ? 1:0;
		r[i] = sum&BN32_MAX;
	}	
	r[0] = r[0] - carry;	
}

void bn32_sub64(bn32 r, const bn32 a)
{
	int i;
	uint32_t carry;
	uint64_t sum;
	
	sum = (uint64_t) r[2*BN32_SIZE-1]-a[BN32_SIZE-1];
	carry = (sum >> BN32_WORD_SIZE) ? 1:0;
	r[2*BN32_SIZE-1] = sum&BN32_MAX;
	
	for(i=BN32_SIZE-2; i>=0; i--)
	{
		sum = (uint64_t) r[i+BN32_SIZE]-a[i]-carry;
		carry = (sum >> BN32_WORD_SIZE) ? 1:0;
		r[i+BN32_SIZE] = sum&BN32_MAX;
	}	
	for(i=BN32_SIZE-1; i>=0; i--)
	{
		sum = (uint64_t) r[i]-carry;
		carry = (sum >> BN32_WORD_SIZE) ? 1:0;
		r[i] = sum&BN32_MAX;
	}
}

// r = r - a
// r is size_r bytes
// a is size_a bytes
// size_a <= size_r
void bn32_sub_nn(bn32 r, uint8_t size_r, const bn32 a, uint8_t size_a)
{
	int i;
	uint32_t carry;
	uint64_t sum;
	
	sum = (uint64_t) r[size_r-1]-a[size_a-1];
	carry = (sum >> BN32_WORD_SIZE) ? 1:0;
	r[size_r-1] = sum&BN32_MAX;
	
	for(i=size_a-2; i>=0; i--)
	{
		sum = (uint64_t) r[i+size_r-size_a]-a[i]-carry;
		carry = (sum >> BN32_WORD_SIZE) ? 1:0;
		r[i+size_r-size_a] = sum&BN32_MAX;
	}	
	if(size_r-size_a)
	{
		for(i=size_r-size_a-1; i>=0; i--)
		{
			sum = (uint64_t) r[i]-carry;
			carry = (sum >> BN32_WORD_SIZE) ? 1:0;
			r[i] = sum&BN32_MAX;
		}
	}
}


void bn32_zero(bn32 r, uint8_t size)
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
void bn32_mod(bn32 r, const bn32 mod, uint8_t size)
{
	while(bn32_cmp_nn(r, size, mod, BN32_SIZE) > 0)
		bn32_sub_nn(r, size, mod, BN32_SIZE);	
}

// reduces c based on septk1256
// c and r 64 byte
void bn32_fast_reduction(bn32 r, const bn32 c)
{
	uint32_t a[BN32_SIZE*2] = {0};	
	bn32 a0,a1;
	bn32 c1 = c;
	bn32 c0 = c + BN32_SIZE;	
		
	bn32_zero(a, BN32_SIZE*2);				
	bn32_add_shift(a, c1, 32);	
	bn32_add_shift(a, c1, 9);
	bn32_add_shift(a, c1, 8);
	bn32_add_shift(a, c1, 7);
	bn32_add_shift(a, c1, 6);
	bn32_add_shift(a, c1, 4);
	bn32_add_shift(a, c1, 0);	
		
	a1 = a;
	a0 = a+BN32_SIZE;
	
	bn32_zero(r, BN32_SIZE*2);
	bn32_add_shift(r, a1, 32);	
	bn32_add_shift(r, a1, 9);
	bn32_add_shift(r, a1, 8);
	bn32_add_shift(r, a1, 7);
	bn32_add_shift(r, a1, 6);
	bn32_add_shift(r, a1, 4);
	bn32_add_shift(r, a1, 0);
	bn32_add_shift(r, a0, 0);
	bn32_add_shift(r, c0, 0);	
	
	while(bn32_cmp_nn(r, BN32_SIZE*2, MOD_P, BN32_SIZE) > 0)
		bn32_sub_nn(r, BN32_SIZE*2, MOD_P, BN32_SIZE);		
}

void bn32_barrett_reduction_p(bn32 r, const bn32 z)
{
	uint8_t i;
	uint32_t q_[BN32_SIZE+1] = {0}; // 33 byte
	uint32_t q_p[BN32_SIZE*2+1] = {0};
	bn32_zero(r, BN32_SIZE+1);
	
	bn32_mul(q_p, z, U0_P, BN32_SIZE+1, 2);
	
	
	for(i=0; i<5; i++)
		q_[BN32_SIZE-i] = q_p[4-i];
	bn32_add_n(q_, z, BN32_SIZE+1);	
	
	
	bn32_mul(q_p, q_, MOD_P, BN32_SIZE+1, BN32_SIZE); // todo: efficient 33 byte multiplication
	
	if(bn32_cmp_n(z+BN32_SIZE-1, q_p+BN32_SIZE, BN32_SIZE+1) < 0)	
		r[0] = 1;	// Adds b^(k+1) if r would be negative
	
	for(i=0; i<BN32_SIZE; i++)	
		r[1+i] = z[7+i];
		
	bn32_sub_n(r, q_p+BN32_SIZE, BN32_SIZE+2);
	
	while(bn32_cmp_nn(r, BN32_SIZE+1, MOD_P, BN32_SIZE) > 0)
	{
		bn32_sub_nn(r, BN32_SIZE+1, MOD_P, BN32_SIZE);
	}
}

void bn32_barrett_reduction_n(bn32 r, const bn32 z)
{
	uint8_t i;
	uint32_t q_[BN32_SIZE+1] = {0}; // 33 byte
	uint32_t q_p[BN32_SIZE*2+1] = {0};
	bn32_zero(r, BN32_SIZE+2);
	
	// the q_ multiplication is split into two parts q_ = z[16:7] + z[16:7]*u0 
	// where u = 100.. + u0
	bn32_mul(q_p, z, U0_N, BN32_SIZE+1, 5);
	
	
	for(i=0; i<5; i++)
		q_[BN32_SIZE-i] = q_p[4-i];
	bn32_add_n(q_, z, BN32_SIZE+1);	
	
	
	bn32_mul(q_p, q_, MOD_0000N+1, BN32_SIZE+1, BN32_SIZE); // todo: efficient 33 byte multiplication
	
	if(bn32_cmp_n(z+BN32_SIZE-1, q_p+BN32_SIZE, BN32_SIZE+1) < 0)	
		r[0] = 1;	// Adds b^(k+1) if r would be negative
	
	for(i=0; i<BN32_SIZE+1; i++)	
		r[1+i] = z[7+i];
		
	bn32_sub_n(r, q_p+BN32_SIZE, BN32_SIZE+2);
	
	while(bn32_cmp_nn(r, BN32_SIZE+2, MOD_N, BN32_SIZE) >= 0) // TODO: zero detection
	{
		bn32_sub_nn(r, BN32_SIZE+2, MOD_N, BN32_SIZE);
	}
}

// r += a << n
// r: 64 bytes
// a: 32 bytes
void bn32_add_shift(bn32 r, const bn32 a, uint8_t n)
{
	uint32_t t;
	uint8_t offset = n/BN32_WORD_SIZE;
	n %= BN32_WORD_SIZE;
	
	int i;
	uint32_t carry;
	uint64_t sum;
	
	t = (a[BN32_SIZE-1]<<n);
	sum = (uint64_t) r[BN32_SIZE*2-1-offset]+t;
	carry = (sum >> BN32_WORD_SIZE) ? 1:0;
	r[BN32_SIZE*2-1-offset] = sum&BN32_MAX;
	
	
	for(i=BN32_SIZE-2; i>=0; i--)
	{				
		sum = (uint64_t) r[i+BN32_SIZE-offset]+carry;
		carry = (n) ? a[i+1]>>(BN32_WORD_SIZE-n) : 0;
		t = a[i]<<n | carry;
		sum += t;
		carry = (sum >> BN32_WORD_SIZE) ? 1:0;
		r[i+BN32_SIZE-offset] = sum&BN32_MAX;
	}	
	
	sum = (uint64_t) r[BN32_SIZE-offset-1]+carry;
	carry = (n) ? a[0]>>(BN32_WORD_SIZE-n) : 0;	
	sum += carry;
	carry = (sum >> BN32_WORD_SIZE) ? 1:0;
	r[BN32_SIZE-offset-1] = sum&BN32_MAX;
	
	for(i=BN32_SIZE-offset-2; i; i--)
	{
		sum = (uint64_t) r[i]+carry;
		carry = (sum >> BN32_WORD_SIZE) ? 1:0;
		r[i] = sum&BN32_MAX;
	}
	r[i] += carry;	
}

void bn32_lshift(bn32 r, uint8_t n)
{
	uint8_t i;
	uint8_t carry;
	uint8_t offset = n/BN32_WORD_SIZE;
	n %= BN32_WORD_SIZE;
	if(offset)
	{
		for(i=0; i<(BN32_SIZE-offset); i++)
		{
			r[i] = r[i+offset];
		}
		for(; i<BN32_SIZE; i++)
		{
			r[i] = 0;
		}
	}
		
	for(i=0; i<BN32_SIZE; i++)
	{
		carry = (i+1==BN32_SIZE) ? r[i+1]>>(BN32_WORD_SIZE-n) : 0;
		r[i] = r[i]<<n | carry;
	}
}

void bn32_rshift1(bn32 r, uint8_t size)
{
	uint8_t i;
	uint32_t carry;		
		
	for(i=size; i>1; i--)
	{
		carry = r[i-2]<<(BN32_WORD_SIZE-1);
		r[i-1] = r[i-1]>>1 | carry;
	}
	r[0] = r[0]>>1;
}

void bn32_lshift1(bn32 r, uint8_t size)
{
	uint8_t i;
	uint32_t carry;		
		
	for(i=0; i<size-1; i++)
	{
		carry = r[i+1]>>(BN32_WORD_SIZE-1);
		r[i] = (r[i]<<1) | carry;
	}
	r[size-1] = r[size-1] << 1;
}

void bn32_rshift1_2s(bn32 r, uint8_t size)
{
	uint8_t i;
	uint32_t carry;		
		
	for(i=size; i>1; i--)
	{
		carry = r[i-2]<<(BN32_WORD_SIZE-1);
		r[i-1] = r[i-1]>>1 | carry;
	}
	if(r[0]&0x80000000)
		r[0] = (r[0]>>1) | 0x80000000;
	else
		r[0] = r[0]>>1;
}	

void bn32_mul(bn32 r, const bn32 x, const bn32 y, uint8_t sizex, uint8_t sizey)
{
	int i,j;	
	uint64_t uv=0;
	
	
	for(i=0; i<sizex+sizey; i++)
		r[i]=0;
		
	for(i=sizex-1; i>=0; i--)
	{
		uv &= BN32_MAX;
		
		for(j=sizey-1; j>=0; j--)
		{
			uv = r[i+j+1]+(uint64_t)x[i]*y[j] + ((uv>>BN32_WORD_SIZE) & BN32_MAX) ;
			r[i+j+1]=uv&BN32_MAX;
		}
		r[i]=((uv>>BN32_WORD_SIZE) & BN32_MAX);
		
	}
}

void bn32_sqr(bn32 r, const bn32 x, uint8_t size)
{
	int16_t i,j,k;
	uint32_t r0 = 0;
	uint32_t r1 = 0;
	uint32_t r2 = 0;
	uint64_t uv, sum;
	uint32_t carry = 0;
	
	for(k=0; k < 2*size-1; k++)
	{
		j = (k >= size-1) ? size-1:k;
		i = (k-j > 0) ? k-j:0;
		
		for(; i <= j; i++)
		{			
			uv = x[size-1-i]*x[size-1-j];
			if(i < j)
			{
				carry = (uv >> 63) ? 1:0;
				uv = uv<<1;
				r2 += carry;
			}
			sum = r0 + (uv&BN32_MAX);
			carry = (sum >> BN32_WORD_SIZE) ? 1:0;
			r0 = sum & BN32_MAX;
			
			sum = r1 +(uv>>8) + carry;
			carry = (sum >> BN32_WORD_SIZE) ? 1:0;
			r1 = sum & BN32_MAX;
			
			r2 += carry;
			
			j--;
		}
		r[size*2-1-k] = r0;
		r0 = r1;
		r1 = r2;
		r2 = 0;
	}
	r[0] = r0;	
}

// r = 3x
// r is sizex+1 bytes
void bn32_mul3(bn32 r, const bn32 x, uint8_t sizex)
{
	r[0] = 0;
	bn32_copy(r+1, x, sizex);
	bn32_lshift1(r, sizex+1);
	bn32_add_n(r, x, sizex+1);
}


uint8_t bn32_is_even_2s(bn32 a, uint8_t size)
{
	if(a[0] & 0x80000000) return (a[size-1] & 0x01);
	return !(a[size-1] & 0x01);
}

uint8_t bn32_is_even(bn32 a, uint8_t size)
{
	return !(a[size-1] & 0x01);
}

uint8_t bn32_is_one(bn32 a, uint8_t size)
{
	uint8_t i = 0;
	
	for(i=0; i<size-1; i++)
	{
		if(a[i]) return 0;
	}
	return a[size-1]==1;
}

void bn32_copy(bn32 r, const bn32 a, uint8_t size)
{
	uint8_t i;
	
	for(i=0; i<size; i++)
		r[i] = a[i];
}

#define X_SIZE (BN32_SIZE*2)

void bn32_invert(bn32 r, const bn32 a, const bn32 p)
{
	uint32_t u[BN32_SIZE];
	uint32_t v[BN32_SIZE];
	uint32_t x1[X_SIZE] = {0};
	uint32_t x2[X_SIZE] = {0};
	
	bn32_copy(u, a, BN32_SIZE);
	bn32_copy(v, p, BN32_SIZE);
	x1[BN32_SIZE*2-1] = 1;
	x2[BN32_SIZE*2-1] = 0;
	
	while(!bn32_is_one(u, BN32_SIZE) && !bn32_is_one(v, BN32_SIZE))
	{
		while(bn32_is_even(u, BN32_SIZE))
		{
			bn32_rshift1(u, BN32_SIZE);
			if(bn32_is_even(x1, X_SIZE))
			{
				bn32_rshift1_2s(x1, X_SIZE);
			} else {
				bn32_add_n32(x1, p, X_SIZE);
				bn32_rshift1_2s(x1, X_SIZE);
			}
		}
		while(bn32_is_even(v, BN32_SIZE))
		{
			bn32_rshift1(v, BN32_SIZE);
			if(bn32_is_even(x2, X_SIZE))
			{
				bn32_rshift1_2s(x2, X_SIZE);
			} else {
				bn32_add_n32(x2, p, X_SIZE);
				bn32_rshift1_2s(x2, X_SIZE);
			}
		}
		if(bn32_cmp(u, v) >= 0)
		{
			bn32_sub_acc(u, v, BN32_SIZE);			
			bn32_sub_acc(x1, x2, X_SIZE);
		} else {
			bn32_sub_acc(v, u, BN32_SIZE);
			bn32_sub_acc(x2, x1, X_SIZE);			
		}
	}
	
	if(bn32_is_one(u, BN32_SIZE))
	{
		if(x1[0] & 0x80000000) bn32_add_n32(x1, p, X_SIZE);
		while(bn32_cmp64(x1, MOD_P) > 0)
			bn32_sub64(x1, MOD_P);	
		bn32_copy(r+2, x1+BN32_SIZE, BN32_SIZE);		
	} else {
		if(x2[0] & 0x80000000) bn32_add_n32(x2, p, X_SIZE);
		while(bn32_cmp64(x2, MOD_P) > 0)
			bn32_sub64(x2, MOD_P);	
		bn32_copy(r+2, x2+BN32_SIZE, BN32_SIZE);		
	}	
}

signed char bn32_cmp_n(const bn32 a, const bn32 b, uint8_t n)
{
	uint8_t i;
	
	for(i=0; i<n; i++)
	{
		if(a[i]>b[i]) return 1;
		if(a[i]<b[i]) return -1;		
	}
	return 0;
}

signed char bn32_cmp64(const bn32 a, const bn32 b)
{
	char i;	
	for(i=0; i<BN32_SIZE; i++)
	{
		if(a[i]) return 1;
	}
	for(i=0; i<BN32_SIZE; i++)
	{
		if(a[i+BN32_SIZE]>b[i]) return 1;
		if(a[i+BN32_SIZE]<b[i]) return -1;		
	}
	return 0;
}

// compares a and b
// a > b   = 1
// a == b  = 0
// a < b   = -1
// requires sizeb <= sizea
signed char bn32_cmp_nn(const bn32 a, uint8_t sizea, const bn32 b, uint8_t sizeb)
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

signed char bn32_cmp(const bn32 a, const bn32 b)
{
	char i;	
	for(i=0; i<BN32_SIZE; i++)
	{
		if(a[i]>b[i]) return 1;
		if(a[i]<b[i]) return -1;		
	}
	return 0;
}

signed char bn32_cmpc(const bn32 a, const uint8_t c, const bn32 b)
{
	char i;
	
	if(c)
	{
		return (c>>7) ? -1:1;
	}
	for(i=0; i<BN32_SIZE; i++)
	{
		if(a[i]>b[i]) return 1;
		if(a[i]<b[i]) return -1;		
	}
	return 0;
}

bn32 bn32_get_p()
{
	return MOD_P;
}

bn32 bn32_get_n()
{
	return MOD_N;
}



uint8_t bn32_is_bit_set(const bn32 a, uint8_t i)
{
	uint32_t a_i = a[BN32_SIZE-i/BN32_WORD_SIZE-1];
	return (a_i >> (i%BN32_WORD_SIZE)) & 0x01;
}
