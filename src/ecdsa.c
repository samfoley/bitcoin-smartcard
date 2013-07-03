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

void point_add_jacobian(bn8 xr, bn8 yr, bn8 zr, bn8 xp, bn8 yp, bn8 zp, bn8 xq, bn8 yq, bn8 zq);
void point_double_jacobian(bn8 xr, bn8 yr, bn8 zr, bn8 xp, bn8 yp, bn8 zp);

void field_mul(bn8 r, bn8 a, bn8 b);
void field_sqr(bn8 r, bn8 a);
void field_double(bn8 r, bn8 a);
void field_mul3(bn8 r, bn8 a);
void field_lshift(bn8 r, bn8 a, uint8_t n);

void ecdsa_test(bn8 m)
{
	uint8_t x1[BN8_SIZE];
	uint8_t y1[BN8_SIZE];
	
	ec_point_mul_jacobian(x1, y1, Gx, Gy, m);
	printf("ECDSA Tests\n\n");
	bn8_print(x1);printf("\n");
	bn8_print(y1);printf("\n");
}

void ecdsa_sign(bn8 r, bn8 s, bn8 z)
{
	
	uint8_t x1[BN8_SIZE];
	uint8_t y1[BN8_SIZE];
	uint8_t k[BN8_SIZE] = {0};	
	
	uint8_t dd[BN8_SIZE*2];
	uint8_t tmp[BN8_SIZE+2] = {0};
	uint8_t tmp2[BN8_SIZE+2] = {0};	
	
	// 1. ?
		
	
	// 2. z = hash(M)			
		
		
	
	// 3. select random k from 0 to n-1
	// TODO: random number generator
	bn8_copy(k, RANDOM_NUMBER, BN8_SIZE);	
	
	
	// 4. (x1,y1) = k * G			
	ec_point_mul_jacobian(x1, y1, Gx, Gy, k);
	
	printf("Jacobian\n");
	bn8_print(x1); printf("\n");
	bn8_print(y1); printf("\n");
	
	/*
	ec_point_mul(x1, y1, Gx, Gy, k);
	
	printf("Affine\n");
	bn8_print(x1); printf("\n");
	bn8_print(y1); printf("\n");
	*/
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
	
	
	uint8_t xJ1[BN8_SIZE] = {0};
	uint8_t yJ1[BN8_SIZE] = {0};
	uint8_t zJ1[BN8_SIZE] = {0};
	
	uint8_t xJ2[BN8_SIZE] = {0};
	uint8_t yJ2[BN8_SIZE] = {0};
	uint8_t zJ2[BN8_SIZE] = {0};
	uint8_t zi[BN8_SIZE+2] = {0};
	
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
				zJ1[BN8_SIZE-1] = 1;
				point_add_jacobian(xJ2, yJ2, zJ2, xq, yq, zJ1, xp, yp, zJ1);	
				bn8_copy(xq, xr, BN8_SIZE);
				bn8_copy(yq, yr, BN8_SIZE);		


				bn8_invert(zi, zJ2, p);
				field_mul(xJ2, xJ2, zi+2);
				field_mul(xJ2, xJ2, zi+2);
				field_mul(yJ2, yJ2, zi+2);
				field_mul(yJ2, yJ2, zi+2);
				field_mul(yJ2, yJ2, zi+2);
				
				if(bn8_cmp(xJ2, xr) != 0 || bn8_cmp(yJ2, yr) != 0)
				{
					printf("Point add\n");
					bn8_print(xp); printf(" xp\n");		
					bn8_print(xJ2); printf(" xJ2\n");
					bn8_print(yJ2); printf(" yJ2\n");
					bn8_print(yp); printf(" yp\n");
				}

				
			}
		}		
		
		point_double(xr, yr, xp, yp);
		zJ1[BN8_SIZE-1] = 1;
		point_double_jacobian(xJ2, yJ2, zJ2, xp, yp, zJ1);		
		bn8_copy(xp, xr, BN8_SIZE);
		bn8_copy(yp, yr, BN8_SIZE);
		
								
		bn8_invert(zi, zJ2, p);
		field_mul(xJ2, xJ2, zi+2);
		field_mul(xJ2, xJ2, zi+2);
		field_mul(yJ2, yJ2, zi+2);
		field_mul(yJ2, yJ2, zi+2);
		field_mul(yJ2, yJ2, zi+2);
		
		if(bn8_cmp(xJ2, xr) != 0 || bn8_cmp(yJ2, yr) != 0)
		{
			printf("Point double\n");
			bn8_print(xp); printf(" xp\n");		
			bn8_print(xJ2); printf(" xJ2\n");
			bn8_print(yJ2); printf(" yJ2\n");
			bn8_print(yp); printf(" yp\n");
		}
	}
	
	bn8_copy(xr, xq, BN8_SIZE);
	bn8_copy(yr, yq, BN8_SIZE);
}

void ec_point_mul_jacobian(bn8 xr, bn8 yr, bn8 xp_, bn8 yp_, bn8 k)
{
	uint8_t xq[BN8_SIZE] = {0};
	uint8_t yq[BN8_SIZE] = {0};
	uint8_t zq[BN8_SIZE] = {0};
	uint8_t xp[BN8_SIZE];
	uint8_t yp[BN8_SIZE];
	uint8_t zp[BN8_SIZE] = {0};
	uint8_t zr[BN8_SIZE];
	uint8_t z_inverse[BN8_SIZE+2];
	uint8_t z3[BN8_SIZE];
	
	// Q at infinity
	xq[BN8_SIZE-1]=1;
	yq[BN8_SIZE-1]=1;
	zq[BN8_SIZE-1]=0;
	uint8_t q_at_infinity = 1;
	
	int i = 0;
	
	bn8_copy(xp, xp_, BN8_SIZE);
	bn8_copy(yp, yp_, BN8_SIZE);
	zp[BN8_SIZE-1] = 1;
	
	for(i=255; i>=0; i--)
	{
		if(!q_at_infinity)
		{
			point_double_jacobian(xr, yr, zr, xq, yq, zq);
			bn8_copy(xq, xr, BN8_SIZE);
			bn8_copy(yq, yr, BN8_SIZE);
			bn8_copy(zq, zr, BN8_SIZE);
		}
		if(bn8_is_bit_set(k,i))
		{
			if(q_at_infinity)
			{
				bn8_copy(xq, xp, BN8_SIZE);
				bn8_copy(yq, yp, BN8_SIZE);
				bn8_copy(zq, zp, BN8_SIZE);
				q_at_infinity=0;
			} else {							
				point_add_jacobian(xr, yr, zr, xq, yq, zq, xp, yp, zp);
				bn8_copy(xq, xr, BN8_SIZE);
				bn8_copy(yq, yr, BN8_SIZE);
				bn8_copy(zq, zr, BN8_SIZE);
			}
		}		
		
	}
	
	bn8_print(xq); printf(" Xq\n");
	bn8_print(yq); printf(" Yq\n");
	bn8_print(zq); printf(" zq\n");
	
	bn8_invert(z_inverse, zq, p);
		
	field_mul(xr, xq, z_inverse+2);
	field_mul(xr, xr, z_inverse+2);
	
	field_mul(yr, yq, z_inverse+2);
	field_mul(yr, yr, z_inverse+2);
	field_mul(yr, yr, z_inverse+2);		
}


void point_add(bn8 xr, bn8 yr, bn8 xp, bn8 yp, bn8 xq, bn8 yq)
{
	uint8_t a[BN8_SIZE];
	uint8_t b[BN8_SIZE];
	uint8_t c[BN8_SIZE];
	uint8_t dd[BN8_SIZE*2];	
	uint8_t lambda[BN8_SIZE];
	
	// lambda = (yq-yp)/(xq-xp)
	bn8_sub(a, yq, yp); // yq-yp	
	bn8_sub(b, xq, xp); // xq-xp
	
	bn8_invert(dd, b, bn8_get_p()); // (xq-xp)^-1
	bn8_copy(c, dd+2, BN8_SIZE);
	field_mul(lambda, a, c); // (yq-yp)/(xq-xp)		
	
	// xr = lambda^2 - xp - xq
	field_sqr(a, lambda); // lambda^2	
	bn8_sub(b, a, xp); // lambda^2 - xp	
	bn8_sub(xr, b, xq); // lambda^2 - xp - xq
		
	// yr = lambda(xp - xr) - yp
	bn8_sub(a, xp, xr); // xp - xr	
	field_mul(b, lambda, a); // lambda(xp-xr)	
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
	field_double(a, yp); // 2yp			
	field_sqr(c, xp); // xp^2					
	field_mul3(b, c); // 3xp^2		
	bn8_invert(r, a, bn8_get_p()); // (2yp)^-1	
	field_mul(lambda, b, r+2); // lambda = (3xp^2+a)(2yp)^-1
	
	// xr = lambda^2 - 2x	
	field_sqr(a, lambda); // lambda^2				
	field_double(b, xp); // 2xp	
	bn8_sub(xr, a, b); // lambda^2 - 2xp
	
	// yr = lambda(xp - xr) - yp
	bn8_sub(a, xp, xr); // xp-xr			
	field_mul(c, lambda, a); // lambda(xp-xr)	
	bn8_sub(yr, c, yp); // lambda(xp-xr) - yp	
}

void point_add_jacobian(bn8 Xr, bn8 Yr, bn8 Zr, bn8 Xp, bn8 Yp, bn8 Zp, bn8 Xq, bn8 Yq, bn8 Zq)
{
	uint8_t A[BN8_SIZE];
	uint8_t B[BN8_SIZE];
	uint8_t C[BN8_SIZE];
	uint8_t D[BN8_SIZE];
	uint8_t E[BN8_SIZE];
	uint8_t F[BN8_SIZE];
	uint8_t G[BN8_SIZE];
	uint8_t H[BN8_SIZE];
	uint8_t I[BN8_SIZE];
	uint8_t t[BN8_SIZE];
	uint8_t t2[BN8_SIZE];
	
	field_sqr(A, Zp);
	
	field_mul(B, Zp, A);
	
	field_mul(C, Xq, A);
	
	field_mul(D, Yq, B);
	
	bn8_sub(E, C, Xp);
	
	bn8_sub(F, D, Yp);
	
	field_sqr(G, E);
	
	field_mul(H, G, E);
	
	field_mul(I, Xp, G);
	
	field_double(t, I);
	bn8_add(t2, H, t);
	field_sqr(t, F);
	bn8_sub(Xr, t, t2);
	
	bn8_sub(t, I, Xr);
	field_mul(t2, F, t);
	field_mul(t, Yp, H);
	bn8_sub(Yr, t2, t);
	
	field_mul(Zr, Zp, E);
}

void point_double_jacobian(bn8 xr, bn8 yr, bn8 zr, bn8 xp, bn8 yp, bn8 zp)
{
	uint8_t A[BN8_SIZE];
	uint8_t B[BN8_SIZE];
	uint8_t C[BN8_SIZE];
	uint8_t D[BN8_SIZE];
	uint8_t t[BN8_SIZE];
	uint8_t t2[BN8_SIZE];
	
	field_sqr(A, yp);
	
	field_lshift(t, xp, 2);
	field_mul(B, t, A);
	
	field_sqr(t, A);
	field_lshift(C, t, 3);
	
	field_sqr(t, xp);
	field_mul3(D, t);
	
	field_sqr(t, D);
	field_double(t2, B);
	bn8_sub(xr, t, t2);
	
	bn8_sub(t, B, xr);
	field_mul(t2, D, t);
	bn8_sub(yr, t2, C);
	
	field_double(t, yp);
	field_mul(zr, t, zp);
}

void field_mul(bn8 r, bn8 a, bn8 b)
{
	uint8_t ab[BN8_SIZE*2];
	uint8_t rr[BN8_SIZE*2];
	
	bn8_mul(ab, a, b, BN8_SIZE, BN8_SIZE);
	bn8_fast_reduction(rr, ab);
	
	bn8_copy(r, rr+BN8_SIZE, BN8_SIZE);
}

void field_sqr(bn8 r, bn8 a)
{
	uint8_t aa[BN8_SIZE*2];
	uint8_t aa2[BN8_SIZE*2];
	uint8_t rr[BN8_SIZE*2];
	
	bn8_mul(aa, a, a, BN8_SIZE, BN8_SIZE);
	/*
	bn8_sqr(aa2, a, BN8_SIZE);	
	if(bn8_cmp_n(aa, aa2, BN8_SIZE*2) != 0) {
		bn8_printn(aa, BN8_SIZE*2); printf(" mul\n");
		bn8_printn(aa2, BN8_SIZE*2); printf(" sqr\n");
	}*/
	bn8_fast_reduction(rr, aa);
	
	bn8_copy(r, rr+BN8_SIZE, BN8_SIZE);
}

void field_double(bn8 r, bn8 a)
{
	uint8_t rr[BN8_SIZE+1];
	
	if(a[0] & 0x80)
	{
		rr[0]=0;
		bn8_copy(rr+1, a, BN8_SIZE);
		bn8_lshift1(rr, BN8_SIZE+1);
		bn8_mod(rr, p, BN8_SIZE+1);
		bn8_copy(r, rr+1, BN8_SIZE);
	} else {
		bn8_copy(r, a, BN8_SIZE);
		bn8_lshift1(r, BN8_SIZE);
		bn8_mod(r, p, BN8_SIZE);
	}
}


void field_mul3(bn8 r, bn8 a)
{
	uint8_t rr[BN8_SIZE+1];
	
	bn8_mul3(rr, a, BN8_SIZE);
	bn8_mod(rr, p, BN8_SIZE+1);
	bn8_copy(r, rr+1, BN8_SIZE);	
}

void field_lshift(bn8 r, bn8 a, uint8_t n)
{
	uint8_t rr[BN8_SIZE+1];	
	rr[0] = 0;
	bn8_copy(rr+1, a, BN8_SIZE);
	while(n)
	{
		bn8_lshift1(rr, BN8_SIZE+1); // TODO: lshift_n implementation
		n--;
	}	
	bn8_mod(rr, p, BN8_SIZE+1);
	bn8_copy(r, rr+1, BN8_SIZE);	
}