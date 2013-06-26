#include <stdint.h>
#include <openssl/bn.h>

#include "bignum8.h"
#include "ecdsa.h"


// Elliptic curve domain parameters for secp256k1
// from sec2_final.pdf
uint8_t Gx[BN8_SIZE] = {0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98};
uint8_t Gy[BN8_SIZE] = {0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8};
uint8_t p[BN8_SIZE] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F};
uint8_t n[BN8_SIZE] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

// Private key
uint8_t dA[BN8_SIZE] = {0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0x44, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x55, 0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x4B, 0xAD, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8};

// TODO RANDOM NUMBER GENERATOR
uint8_t RANDOM_NUMBER[BN8_SIZE] = {0x67, 0x54, 0xc2, 0xe3, 0x1d, 0x7d, 0x70, 0xdf, 0x69, 0x73, 0x2f, 0x98, 0x25, 0x06, 0xfc, 0x6f, 0xf1, 0x9d, 0x60, 0xc7, 0xef, 0xf2, 0x52, 0xd3, 0xa6, 0x14, 0xca, 0x4e, 0xaa, 0x2c, 0x25, 0xae};

void point_add(bn8 xr, bn8 yr, bn8 xp, bn8 yp, bn8 xq, bn8 yq);
void point_double(bn8 xr, bn8 yr, bn8 xp, bn8 yp);

void ecdsa_test(bn8 m)
{
	uint8_t x1[BN8_SIZE];
	uint8_t y1[BN8_SIZE];
	
	ec_point_mul(x1, y1, Gx, Gy, m);
	printf("ECDSA Tests\n\n");
	bn8_print(x1);printf("\n");
	bn8_print(y1);printf("\n");
}

void ecdsa_sign(bn8 r, bn8 s, bn8 z)
{
	
	uint8_t x1[BN8_SIZE];
	uint8_t y1[BN8_SIZE];
	uint8_t k[BN8_SIZE];	
	
	uint8_t dd[BN8_SIZE*2];
	uint8_t tmp[BN8_SIZE+2] = {0};
	uint8_t tmp2[BN8_SIZE+2] = {0};	
	
	// 1. ?
		
	
	// 2. z = hash(M)			
		
		
	
	// 3. select random k from 0 to n-1
	// TODO: random number generator
	bn8_copy(k, RANDOM_NUMBER, BN8_SIZE);
	
	
	// 4. (x1,y1) = k * G			
	ec_point_mul(x1, y1, Gx, Gy, k);
	
	// 5. r = x1 (mod n)	
	bn8_copy(r, x1, BN8_SIZE);
	bn8_mod(r, bn8_get_n(), BN8_SIZE);
	
	// 6. s = k^-1(z + rdA) (mod n)	
	bn8_mul(dd, r, dA, BN8_SIZE, BN8_SIZE); // r*dA
	bn8_printn(r, BN8_SIZE); printf("r \n");
	bn8_printn(dA, BN8_SIZE); printf(" dA\n");
	bn8_printn(dd, BN8_SIZE*2); printf(" dd\n ");
	bn8_barrett_reduction_n(tmp, dd); // r*dA (mod n)
	bn8_add_n(tmp+1, z, BN8_SIZE+1); // z + r*dA
	bn8_mod(tmp+1, bn8_get_n(), BN8_SIZE+1); // (z + rdA) (mod n)
	
	bn8_invert(tmp2, k, bn8_get_n()); // k^-1
	bn8_mul(dd, tmp+2, tmp2+2, BN8_SIZE, BN8_SIZE); // k^-1(z + rdA) (mod n)
	bn8_zero(tmp, BN8_SIZE+2);
	bn8_barrett_reduction_n(tmp, dd);

	bn8_copy(s, tmp+2, BN8_SIZE);
}

void ec_point_mul(bn8 xr, bn8 yr, bn8 xp_, bn8 yp_, bn8 k)
{
	uint8_t xq[BN8_SIZE] = {0};
	uint8_t yq[BN8_SIZE] = {0};
	uint8_t xp[BN8_SIZE];
	uint8_t yp[BN8_SIZE];
	uint8_t q_at_infinity = 1;
	
	int i = 0;
	
	bn8_copy(xp, xp_, BN8_SIZE);
	bn8_copy(yp, yp_, BN8_SIZE);
	
	for(i=0; i<256; i++)
	{
		if(bn8_is_bit_set(k,i))
		{
			if(q_at_infinity)
			{
				bn8_copy(xq, xp, BN8_SIZE);
				bn8_copy(yq, yp, BN8_SIZE);
				q_at_infinity=0;
			} else {							
				point_add(xr, yr, xq, yq, xp, yp);
				bn8_copy(xq, xr, BN8_SIZE);
				bn8_copy(yq, yr, BN8_SIZE);
			}
		}		
		point_double(xr, yr, xp, yp);
		bn8_copy(xp, xr, BN8_SIZE);
		bn8_copy(yp, yr, BN8_SIZE);
	}
	
	bn8_copy(xr, xq, BN8_SIZE);
	bn8_copy(yr, yq, BN8_SIZE);
}

void point_add(bn8 xr, bn8 yr, bn8 xp, bn8 yp, bn8 xq, bn8 yq)
{
	uint8_t a[BN8_SIZE];
	uint8_t b[BN8_SIZE];
	uint8_t c[BN8_SIZE];
	uint8_t dd[BN8_SIZE*2];
	uint8_t r[BN8_SIZE+2];
	uint8_t lambda[BN8_SIZE];	
	
	// lambda = (yq-yp)/(xq-xp)
	bn8_sub(a, yq, yp); // yq-yp	
	bn8_sub(b, xq, xp); // xq-xp
	
	bn8_invert(dd, b, bn8_get_p()); // (xq-xp)^-1
	bn8_copy(c, dd+2, BN8_SIZE);
	bn8_mul(dd, a, c, BN8_SIZE, BN8_SIZE); // (yq-yp)/(xq-xp)
	bn8_barrett_reduction_p(r, dd);
	bn8_copy(lambda, r+2, BN8_SIZE);
	
	
	// xr = lambda^2 - xp - xq
	bn8_mul(dd, lambda, lambda, BN8_SIZE, BN8_SIZE); // lambda^2
	bn8_barrett_reduction_p(r, dd);
	bn8_copy(a, r+2, BN8_SIZE);
	bn8_sub(b, a, xp); // lambda^2 - xp	
	bn8_sub(xr, b, xq); // lambda^2 - xp - xq
	
	
	// yr = lambda(xp - xr) - yp
	bn8_sub(a, xp, xr); // xp - xr	
	bn8_mul(dd, lambda, a, BN8_SIZE, BN8_SIZE); // lambda(xp-xr)
	bn8_barrett_reduction_p(r, dd);
	bn8_copy(b, r+2, BN8_SIZE);	
	bn8_sub(yr, b, yp); // lambda(xp-xr) - yp				
}

void point_double(bn8 xr, bn8 yr, bn8 xp, bn8 yp)
{
	uint8_t a[BN8_SIZE];
	uint8_t b[BN8_SIZE];
	uint8_t c[BN8_SIZE];
	uint8_t dd[BN8_SIZE*2];
	uint8_t r[BN8_SIZE+2];
	uint8_t lambda[BN8_SIZE];
	
	
	// lambda = (3x^2 + a)/2y
	r[0]=0;
	bn8_copy(r+1, yp, BN8_SIZE);
	bn8_lshift1(r, BN8_SIZE+1); // 2yp		
	bn8_mod(r, bn8_get_p(), BN8_SIZE+1);
	bn8_copy(a, r+1, BN8_SIZE);
	
	bn8_mul(dd, xp, xp, BN8_SIZE, BN8_SIZE); // xp^2		
	bn8_barrett_reduction_p(r, dd);		
	
	
	bn8_mul3(dd, r+2, BN8_SIZE); // 3xp^2
	bn8_mod(dd, bn8_get_p(), BN8_SIZE+1);
	bn8_copy(b, dd+1, BN8_SIZE);
	
	bn8_invert(r, a, bn8_get_p()); // (2yp)^-1
	
	bn8_mul(dd, b, r+2, BN8_SIZE, BN8_SIZE); // lambda = (3xp^2+a)(2yp)^-1
	bn8_barrett_reduction_p(r, dd);
	bn8_copy(lambda, r+2, BN8_SIZE);
	
	
	// xr = lambda^2 - 2x	
	bn8_mul(dd, lambda, lambda, BN8_SIZE, BN8_SIZE); // lambda^2
	bn8_barrett_reduction_p(r, dd);
	bn8_copy(a, r+2, BN8_SIZE);
		
	bn8_copy(r+1, xp, BN8_SIZE);
	bn8_lshift1(r, BN8_SIZE+1); // 2xp
	bn8_mod(r, bn8_get_p(), BN8_SIZE+1);
		
	bn8_sub(xr, a, r+1); // lambda^2 - 2xp
	
	// yr = lambda(xp - xr) - yp
	bn8_sub(a, xp, xr); // xp-xr			
	bn8_mul(dd, lambda, a, BN8_SIZE, BN8_SIZE); // lambda(xp-xr)
	bn8_barrett_reduction_p(r, dd);	
	bn8_sub(yr, r+2, yp); // lambda(xp-xr) - yp	
}