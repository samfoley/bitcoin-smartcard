#include <stdint.h>
#include <openssl/bn.h>

#include "bignum32.h"
#include "ecdsa.h"


// Elliptic curve domain parameters for secp256k1
// from sec2_final.pdf
uint32_t Gx[BN32_SIZE] = {0x79BE667E, 0xF9DCBBAC, 0x55A06295, 0xCE870B07, 0x029BFCDB, 0x2DCE28D9, 0x59F2815B, 0x16F81798};
uint32_t Gy[BN32_SIZE] = {0x483ADA77, 0x26A3C465, 0x5DA4FBFC, 0x0E1108A8, 0xFD17B448, 0xA6855419, 0x9C47D08F, 0xFB10D4B8};
uint32_t p[BN32_SIZE] = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFC2F};
uint32_t n[BN32_SIZE] = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xBAAEDCE6, 0xAF48A03B, 0xBFD25E8C, 0xD0364141};

// Private key
uint32_t dA[BN32_SIZE] = {0x5e9d0420, 0x7c01614d, 0x361cc9e5, 0x7d795d5c, 0xa77b4d9e, 0x2bf97fd1, 0x2df0e28e, 0xfb515d74};

// TODO RANDOM NUMBER GENERATOR
uint32_t RANDOM_NUMBER[BN32_SIZE] = {0x6754c2e3, 0x1d7d70df, 0x69732f98, 0x2506fc6f, 0xf19d60c7, 0xeff252d3, 0xa614ca4e, 0xaa2c25ae};

/*
TEST VECTORS

m = 1B22644A7BE026548810C378D0B2994EEFA6D2B9881803CB02CEFF865287D1B9
X = F73C65EAD01C5126F28F442D087689BFA08E12763E0CEC1D35B01751FD735ED3
Y = F449A8376906482A84ED01479BD18882B919C140D638307F0C0934BA12590BDE

*/

void point_add(bn32 xr, bn32 yr, bn32 xp, bn32 yp, bn32 xq, bn32 yq);
void point_double(bn32 xr, bn32 yr, bn32 xp, bn32 yp);

void point_add_jacobian(bn32 xr, bn32 yr, bn32 zr, bn32 xp, bn32 yp, bn32 zp, bn32 xq, bn32 yq, bn32 zq);
void point_double_jacobian(bn32 xr, bn32 yr, bn32 zr, bn32 xp, bn32 yp, bn32 zp);

void field_mul(bn32 r, bn32 a, bn32 b);
void field_sqr(bn32 r, bn32 a);
void field_double(bn32 r, bn32 a);
void field_mul3(bn32 r, bn32 a);
void field_lshift(bn32 r, bn32 a, uint8_t n);

void ecdsa_test(bn32 m)
{
	uint32_t x1[BN32_SIZE];
	uint32_t y1[BN32_SIZE];
	
	ec_point_mul_jacobian(x1, y1, Gx, Gy, m);
	printf("ECDSA Tests\n\n");
	bn32_print(x1);printf("\n");
	bn32_print(y1);printf("\n");
}

void ecdsa_sign(uint8_t *r_, uint8_t *s_, uint8_t *hash)
{
	uint32_t r[BN32_SIZE];
	uint32_t s[BN32_SIZE];
	uint32_t z[BN32_SIZE];
	uint32_t x1[BN32_SIZE];
	uint32_t y1[BN32_SIZE];
	uint32_t k[BN32_SIZE] = {0};	
	
	uint32_t dd[BN32_SIZE*2];
	uint32_t tmp[BN32_SIZE+2] = {0};
	uint32_t tmp2[BN32_SIZE+2] = {0};	
	
	// 1. Convert to bignum		
	bn32_from_bin(z, hash);
	
	// 2. z = hash(M)							
	
	// 3. select random k from 0 to n-1
	// TODO: random number generator
	bn32_copy(k, RANDOM_NUMBER, BN32_SIZE);	
		
	// 4. (x1,y1) = k * G			
	ec_point_mul_jacobian(x1, y1, Gx, Gy, k);
	
	// 5. r = x1 (mod n)	
	bn32_copy(r, x1, BN32_SIZE);
	bn32_mod(r, bn32_get_n(), BN32_SIZE);
	
	// 6. s = k^-1(z + rdA) (mod n)	
	bn32_mul(dd, r, dA, BN32_SIZE, BN32_SIZE); // r*dA
	
	bn32_barrett_reduction_n(tmp, dd); // r*dA (mod n)
	bn32_add_n(tmp+1, z, BN32_SIZE+1); // z + r*dA
	bn32_mod(tmp+1, bn32_get_n(), BN32_SIZE+1); // (z + rdA) (mod n)
	
	bn32_invert(tmp2, k, bn32_get_n()); // k^-1
	bn32_mul(dd, tmp+2, tmp2+2, BN32_SIZE, BN32_SIZE); // k^-1(z + rdA) (mod n)
	bn32_zero(tmp, BN32_SIZE+2);
	bn32_barrett_reduction_n(tmp, dd);

	bn32_copy(s, tmp+2, BN32_SIZE);
	
	bn32_to_bin(r_, r);
	bn32_to_bin(s_, s);
}

void ecdsa_set_private_key(bn32 key)
{
	bn32_copy(dA, key, BN32_SIZE);
}

void ecdsa_get_public_key(bn32 key)
{
	uint32_t xr[BN32_SIZE] = {0};
	uint32_t yr[BN32_SIZE] = {0};
	ec_point_mul_jacobian(xr, yr, Gx, Gy, dA);
}






void ec_point_mul_jacobian(bn32 xr, bn32 yr, bn32 xp_, bn32 yp_, bn32 k)
{
	uint32_t xq[BN32_SIZE] = {0};
	uint32_t yq[BN32_SIZE] = {0};
	uint32_t zq[BN32_SIZE] = {0};
	uint32_t xp[BN32_SIZE];
	uint32_t yp[BN32_SIZE];
	uint32_t zp[BN32_SIZE] = {0};
	uint32_t zr[BN32_SIZE];
	uint32_t z_inverse[BN32_SIZE+2];
	uint32_t z3[BN32_SIZE];
	
	// Q at infinity
	xq[BN32_SIZE-1]=1;
	yq[BN32_SIZE-1]=1;
	zq[BN32_SIZE-1]=0;
	uint8_t q_at_infinity = 1;
	
	int i = 0;
	
	bn32_copy(xp, xp_, BN32_SIZE);
	bn32_copy(yp, yp_, BN32_SIZE);
	zp[BN32_SIZE-1] = 1;
	
	for(i=255; i>=0; i--)
	{
		if(!q_at_infinity)
		{
			point_double_jacobian(xr, yr, zr, xq, yq, zq);
			bn32_copy(xq, xr, BN32_SIZE);
			bn32_copy(yq, yr, BN32_SIZE);
			bn32_copy(zq, zr, BN32_SIZE);
		}
		if(bn32_is_bit_set(k,i))
		{
			if(q_at_infinity)
			{
				bn32_copy(xq, xp, BN32_SIZE);
				bn32_copy(yq, yp, BN32_SIZE);
				bn32_copy(zq, zp, BN32_SIZE);
				q_at_infinity=0;
			} else {							
				point_add_jacobian(xr, yr, zr, xq, yq, zq, xp, yp, zp);
				bn32_copy(xq, xr, BN32_SIZE);
				bn32_copy(yq, yr, BN32_SIZE);
				bn32_copy(zq, zr, BN32_SIZE);
			}
		}		
		
	}		
	
	bn32_invert(z_inverse, zq, p);
		
	field_mul(xr, xq, z_inverse+2);
	field_mul(xr, xr, z_inverse+2);
	
	field_mul(yr, yq, z_inverse+2);
	field_mul(yr, yr, z_inverse+2);
	field_mul(yr, yr, z_inverse+2);		
}


void point_add(bn32 xr, bn32 yr, bn32 xp, bn32 yp, bn32 xq, bn32 yq)
{
	uint32_t a[BN32_SIZE];
	uint32_t b[BN32_SIZE];
	uint32_t c[BN32_SIZE];
	uint32_t dd[BN32_SIZE*2];	
	uint32_t lambda[BN32_SIZE];
	
	// lambda = (yq-yp)/(xq-xp)
	bn32_sub(a, yq, yp); // yq-yp	
	bn32_sub(b, xq, xp); // xq-xp
	
	bn32_invert(dd, b, bn32_get_p()); // (xq-xp)^-1
	bn32_copy(c, dd+2, BN32_SIZE);
	field_mul(lambda, a, c); // (yq-yp)/(xq-xp)		
	
	// xr = lambda^2 - xp - xq
	field_sqr(a, lambda); // lambda^2	
	bn32_sub(b, a, xp); // lambda^2 - xp	
	bn32_sub(xr, b, xq); // lambda^2 - xp - xq
		
	// yr = lambda(xp - xr) - yp
	bn32_sub(a, xp, xr); // xp - xr	
	field_mul(b, lambda, a); // lambda(xp-xr)	
	bn32_sub(yr, b, yp); // lambda(xp-xr) - yp				
}

void point_double(bn32 xr, bn32 yr, bn32 xp, bn32 yp)
{
	uint32_t a[BN32_SIZE];
	uint32_t b[BN32_SIZE];
	uint32_t c[BN32_SIZE];
	uint32_t dd[BN32_SIZE*2];
	uint32_t r[BN32_SIZE+2];	
	uint32_t lambda[BN32_SIZE];
	
	
	// lambda = (3x^2 + a)/2y		
	field_double(a, yp); // 2yp			
	field_sqr(c, xp); // xp^2					
	field_mul3(b, c); // 3xp^2		
	bn32_invert(r, a, bn32_get_p()); // (2yp)^-1	
	field_mul(lambda, b, r+2); // lambda = (3xp^2+a)(2yp)^-1
	
	// xr = lambda^2 - 2x	
	field_sqr(a, lambda); // lambda^2				
	field_double(b, xp); // 2xp	
	bn32_sub(xr, a, b); // lambda^2 - 2xp
	
	// yr = lambda(xp - xr) - yp
	bn32_sub(a, xp, xr); // xp-xr			
	field_mul(c, lambda, a); // lambda(xp-xr)	
	bn32_sub(yr, c, yp); // lambda(xp-xr) - yp	
}

void point_add_jacobian(bn32 Xr, bn32 Yr, bn32 Zr, bn32 Xp, bn32 Yp, bn32 Zp, bn32 Xq, bn32 Yq, bn32 Zq)
{
	uint32_t A[BN32_SIZE];
	uint32_t B[BN32_SIZE];
	uint32_t C[BN32_SIZE];
	uint32_t D[BN32_SIZE];
	uint32_t E[BN32_SIZE];
	uint32_t F[BN32_SIZE];
	uint32_t G[BN32_SIZE];
	uint32_t H[BN32_SIZE];
	uint32_t I[BN32_SIZE];
	uint32_t t[BN32_SIZE];
	uint32_t t2[BN32_SIZE];
	
	field_sqr(A, Zp);
	
	field_mul(B, Zp, A);
	
	field_mul(C, Xq, A);
	
	field_mul(D, Yq, B);
	
	bn32_sub(E, C, Xp);
	
	bn32_sub(F, D, Yp);
	
	field_sqr(G, E);
	
	field_mul(H, G, E);
	
	field_mul(I, Xp, G);
	
	field_double(t, I);
	bn32_add(t2, H, t);
	field_sqr(t, F);
	bn32_sub(Xr, t, t2);
	
	bn32_sub(t, I, Xr);
	field_mul(t2, F, t);
	field_mul(t, Yp, H);
	bn32_sub(Yr, t2, t);
	
	field_mul(Zr, Zp, E);
}

void point_double_jacobian(bn32 xr, bn32 yr, bn32 zr, bn32 xp, bn32 yp, bn32 zp)
{
	uint32_t A[BN32_SIZE];
	uint32_t B[BN32_SIZE];
	uint32_t C[BN32_SIZE];
	uint32_t D[BN32_SIZE];
	uint32_t t[BN32_SIZE];
	uint32_t t2[BN32_SIZE];
	
	field_sqr(A, yp);
	
	field_lshift(t, xp, 2);
	field_mul(B, t, A);
	
	field_sqr(t, A);
	field_lshift(C, t, 3);
	
	field_sqr(t, xp);
	field_mul3(D, t);
	
	field_sqr(t, D);
	field_double(t2, B);
	bn32_sub(xr, t, t2);
	
	bn32_sub(t, B, xr);
	field_mul(t2, D, t);
	bn32_sub(yr, t2, C);
	
	field_double(t, yp);
	field_mul(zr, t, zp);
}

void field_mul(bn32 r, bn32 a, bn32 b)
{
	uint32_t ab[BN32_SIZE*2];
	uint32_t rr[BN32_SIZE*2];
	
	bn32_mul(ab, a, b, BN32_SIZE, BN32_SIZE);
	bn32_fast_reduction(rr, ab);
	
	bn32_copy(r, rr+BN32_SIZE, BN32_SIZE);
}

void field_sqr(bn32 r, bn32 a)
{
	uint32_t aa[BN32_SIZE*2];
	uint32_t aa2[BN32_SIZE*2];
	uint32_t rr[BN32_SIZE*2];
	
	bn32_mul(aa, a, a, BN32_SIZE, BN32_SIZE);
	/*
	bn32_sqr(aa2, a, BN32_SIZE);	
	if(bn32_cmp_n(aa, aa2, BN32_SIZE*2) != 0) {
		bn32_printn(aa, BN32_SIZE*2); printf(" mul\n");
		bn32_printn(aa2, BN32_SIZE*2); printf(" sqr\n");
	}*/
	bn32_fast_reduction(rr, aa);
	
	bn32_copy(r, rr+BN32_SIZE, BN32_SIZE);
}

void field_double(bn32 r, bn32 a)
{
	uint32_t rr[BN32_SIZE+1];
	
	if(a[0] & 0x80000000)
	{
		rr[0]=0;
		bn32_copy(rr+1, a, BN32_SIZE);
		bn32_lshift1(rr, BN32_SIZE+1);
		bn32_mod(rr, p, BN32_SIZE+1);
		bn32_copy(r, rr+1, BN32_SIZE);
	} else {
		bn32_copy(r, a, BN32_SIZE);
		bn32_lshift1(r, BN32_SIZE);
		bn32_mod(r, p, BN32_SIZE);
	}
}


void field_mul3(bn32 r, bn32 a)
{
	uint32_t rr[BN32_SIZE+1];
	
	bn32_mul3(rr, a, BN32_SIZE);
	bn32_mod(rr, p, BN32_SIZE+1);
	bn32_copy(r, rr+1, BN32_SIZE);	
}

void field_lshift(bn32 r, bn32 a, uint8_t n)
{
	uint32_t rr[BN32_SIZE+1];	
	rr[0] = 0;
	bn32_copy(rr+1, a, BN32_SIZE);
	while(n)
	{
		bn32_lshift1(rr, BN32_SIZE+1); // TODO: lshift_n implementation
		n--;
	}	
	bn32_mod(rr, p, BN32_SIZE+1);
	bn32_copy(r, rr+1, BN32_SIZE);	
}



// Affine Old implementation
/*
void ec_point_mul(bn32 xr, bn32 yr, bn32 xp_, bn32 yp_, bn32 k)
{
	uint8_t xq[BN32_SIZE] = {0};
	uint8_t yq[BN32_SIZE] = {0};
	uint8_t xp[BN32_SIZE];
	uint8_t yp[BN32_SIZE];
	uint8_t q_at_infinity = 1;
	
	
	uint8_t xJ1[BN32_SIZE] = {0};
	uint8_t yJ1[BN32_SIZE] = {0};
	uint8_t zJ1[BN32_SIZE] = {0};
	
	uint8_t xJ2[BN32_SIZE] = {0};
	uint8_t yJ2[BN32_SIZE] = {0};
	uint8_t zJ2[BN32_SIZE] = {0};
	uint8_t zi[BN32_SIZE+2] = {0};
	
	int i = 0;
	
	bn32_copy(xp, xp_, BN32_SIZE);
	bn32_copy(yp, yp_, BN32_SIZE);
	
	for(i=0; i<256; i++)
	{
		if(bn32_is_bit_set(k,i))
		{
			if(q_at_infinity)
			{
				bn32_copy(xq, xp, BN32_SIZE);
				bn32_copy(yq, yp, BN32_SIZE);
				q_at_infinity=0;
			} else {							
				point_add(xr, yr, xq, yq, xp, yp);
				zJ1[BN32_SIZE-1] = 1;
				point_add_jacobian(xJ2, yJ2, zJ2, xq, yq, zJ1, xp, yp, zJ1);	
				bn32_copy(xq, xr, BN32_SIZE);
				bn32_copy(yq, yr, BN32_SIZE);		


				bn32_invert(zi, zJ2, p);
				field_mul(xJ2, xJ2, zi+2);
				field_mul(xJ2, xJ2, zi+2);
				field_mul(yJ2, yJ2, zi+2);
				field_mul(yJ2, yJ2, zi+2);
				field_mul(yJ2, yJ2, zi+2);
				
				if(bn32_cmp(xJ2, xr) != 0 || bn32_cmp(yJ2, yr) != 0)
				{
					printf("Point add\n");
					bn32_print(xp); printf(" xp\n");		
					bn32_print(xJ2); printf(" xJ2\n");
					bn32_print(yJ2); printf(" yJ2\n");
					bn32_print(yp); printf(" yp\n");
				}

				
			}
		}		
		
		point_double(xr, yr, xp, yp);
		zJ1[BN32_SIZE-1] = 1;
		point_double_jacobian(xJ2, yJ2, zJ2, xp, yp, zJ1);		
		bn32_copy(xp, xr, BN32_SIZE);
		bn32_copy(yp, yr, BN32_SIZE);
		
								
		bn32_invert(zi, zJ2, p);
		field_mul(xJ2, xJ2, zi+2);
		field_mul(xJ2, xJ2, zi+2);
		field_mul(yJ2, yJ2, zi+2);
		field_mul(yJ2, yJ2, zi+2);
		field_mul(yJ2, yJ2, zi+2);
		
		if(bn32_cmp(xJ2, xr) != 0 || bn32_cmp(yJ2, yr) != 0)
		{
			printf("Point double\n");
			bn32_print(xp); printf(" xp\n");		
			bn32_print(xJ2); printf(" xJ2\n");
			bn32_print(yJ2); printf(" yJ2\n");
			bn32_print(yp); printf(" yp\n");
		}
	}
	
	bn32_copy(xr, xq, BN32_SIZE);
	bn32_copy(yr, yq, BN32_SIZE);
}


*/