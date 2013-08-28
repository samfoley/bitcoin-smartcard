#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include "base58.h"
#include "bignum32.h"
#include "ecdsa.h"


uint32_t bn32_buffer_1[BN32_SIZE] = { 0 };
uint32_t bn32_buffer_2[BN32_SIZE] = { 0 };
uint32_t bn32_buffer_3[BN32_SIZE] = { 0 };
uint32_t bn32_buffer_4[BN32_SIZE] = { 0 };
uint32_t bn32_buffer_r[BN32_SIZE*2] = { 0 };

const char priv_key_b58[] = "cSoZxDuKeR2TWRyQp8ZXAgPogL281Y786ZogzfmK13c1RBNRcmYS";

typedef struct
{
	BIGNUM *x; 
	BIGNUM *y;
	bool at_infinity;
} Point;

typedef struct 
{
	BIGNUM *a;
	BIGNUM *b;
	BIGNUM *p;
} Curve;

// Secp256k1 Parameters
const char p_hex[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
const char b_hex[] = "0000000000000000000000000000000000000000000000000000000000000007";
const char G_hex[] = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
const char G1_hex[] = "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
const char Gx_hex[] = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
const char Gy_hex[] = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
const char Da_hex[] = "5e9d04207c01614d361cc9e57d795d5ca77b4d9e2bf97fd12df0e28efb515d74";
const char n_hex[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
int h = 1;
BN_CTX *ctx = NULL;
BIGNUM *mod = NULL;
BIGNUM *dA_BN = NULL;

ECDSA_SIG* ECDSA_test_sign(unsigned char *digest, int digest_len, unsigned char *sig, int *siglen);

Point* point_new(BIGNUM *x, BIGNUM *y);
Point* point_at_infinity();

void ec_point_mul(bn32 xr, bn32 yr, bn32 xp, bn32 yp, bn32 k);
void point_double(bn32 xr, bn32 yr, bn32 xp, bn32 yp);
void point_add(bn32 xr, bn32 y, bn32 xp, bn32 yp, bn32 xq, bn32 yq);

void print_bn(BIGNUM *b)
{
	BN_print_fp(stdout, b);
}

int main()
{
	int        ret,i;
	unsigned char *sig=NULL;
	int siglen=0;
	EC_KEY    *eckey = EC_KEY_new();
	EC_GROUP *group     = NULL;
	unsigned char digest[32] = { 0 };
	digest[0]=1;
	digest[2]=10;
	digest[5]=15;
	digest[9]=17;
	digest[12]=59;
	digest[30]=87;
	unsigned char priv_key_bin[40];	
	ECDSA_SIG *ecsig = ECDSA_SIG_new();
    EC_POINT *pub_key = NULL;
	BIGNUM *tmp = BN_new();
	
	
	uint32_t digest_bn[BN32_SIZE];
	uint32_t r_bn[BN32_SIZE];
	uint32_t s_bn[BN32_SIZE];
	
	uint8_t r[32];
	uint8_t s[32];
	uint32_t m[BN32_SIZE] = {0x1B22644A, 0x7BE02654, 0x8810C378, 0xD0B2994E, 0xEFA6D2B9, 0x881803CB, 0x02CEFF86, 0x5287D1B9};
	
	
	if ((ctx = BN_CTX_new()) == NULL)
	{
		fprintf(stderr,"BN_CTX fail\n");
        return -1;
	}

	// calculate u
	BIGNUM *b2k = BN_new();
	BIGNUM *u = BN_new();
	BIGNUM *n = BN_new();
	BN_hex2bn(&n, n_hex);
	BN_one(b2k);
	BN_lshift(b2k, b2k, 512);
	BN_div(u, NULL, b2k, n, ctx);
	printf("u: ");
	BN_print_fp(stdout, u);printf("\n");
	
	// test bn32_lshift
	bn32_buffer_1[BN32_SIZE-1] = 0xff;
	bn32_buffer_1[BN32_SIZE-1] = 0xba;
	bn32_lshift(bn32_buffer_1, 9);
	printf("lshift ");
	bn32_print(bn32_buffer_1);
	printf("\n\n");
	bn32_buffer_1[BN32_SIZE-1] = 0x00;
	
	// test bn32_add_shift
	printf("addshift\n\n");
	bn32_buffer_1[BN32_SIZE-1] = 1;
	bn32_buffer_1[BN32_SIZE-2] = 0xab;
	bn32_buffer_1[BN32_SIZE-3] = 0xff;
	bn32_add_shift(bn32_buffer_r, bn32_buffer_1, 4);
	bn32_add_shift(bn32_buffer_r, bn32_buffer_1, 32);
	
	bn32_buffer_2[BN32_SIZE-1] = 0xff;
	bn32_add_shift(bn32_buffer_r, bn32_buffer_2, 0);
	bn32_print(bn32_buffer_r); bn32_print(bn32_buffer_r+BN32_SIZE);
	printf("\n\n");
	
	// test rshift
	bn32_print(bn32_buffer_1); printf("\nrshift\n");
	bn32_rshift1(bn32_buffer_1, BN32_SIZE); 
	bn32_print(bn32_buffer_1); printf("\n");
	// test rshift
	printf("\nlshift\n");
	bn32_lshift1(bn32_buffer_1, BN32_SIZE); 
	bn32_print(bn32_buffer_1); printf("\n");
	// test 3x
	printf("3x\n");
	bn32_mul3(bn32_buffer_r, bn32_buffer_1, BN32_SIZE);
	bn32_printn(bn32_buffer_r, BN32_SIZE+1); printf("\n");
	
	// Point add/double tests
	
	Curve test_curve;
	test_curve.p = BN_new();
	test_curve.a = BN_new();
	test_curve.b = BN_new();
	unsigned char test_a = 4;	
	unsigned char test_b = 20;	
	unsigned char test_p = 29;
	
	BN_bin2bn(&test_a, 1, test_curve.a);
	BN_bin2bn(&test_b, 1, test_curve.b);
	BN_bin2bn(&test_p, 1, test_curve.p);
	
	unsigned char test_x1 = 5;
	unsigned char test_y1 = 22;
	unsigned char test_x2 = 16;
	unsigned char test_y2 = 27;
	
	Point *test1 = point_new(BN_new(), BN_new());
	Point *test2 = point_new(BN_new(), BN_new());
	
	BN_bin2bn(&test_x1, 1, test1->x);
	BN_bin2bn(&test_y1, 1, test1->y);
	BN_bin2bn(&test_x2, 1, test2->x);
	BN_bin2bn(&test_y2, 1, test2->y);
	/*
	printf("\nTest a: "); BN_print_fp(stdout, test_curve.a);
	printf("\nTest b: "); BN_print_fp(stdout, test_curve.b);
	printf("\nTest p: "); BN_print_fp(stdout, test_curve.p);
	
	printf("\nTest1 x: "); BN_print_fp(stdout, test1->x);
	printf("\nTest1 y: "); BN_print_fp(stdout, test1->y);
	printf("\nTest2 x: "); BN_print_fp(stdout, test2->x);
	printf("\nTest2 y: "); BN_print_fp(stdout, test2->y);
	
	Point *test3 = point_add(test1, test2, &test_curve);
	printf("\nTest add x: "); BN_print_fp(stdout, test3->x);
	printf("\nTest add y: "); BN_print_fp(stdout, test3->y);
	printf("\n\n");
	
	test3 = point_double(test1, &test_curve);
	printf("Test double x: "); BN_print_fp(stdout, test3->x);
	printf("\nTest double y: "); BN_print_fp(stdout, test3->y);
	printf("\n\n");
	*/
	dA_BN = BN_new();
	_blkmk_b58tobin(priv_key_bin, sizeof(priv_key_bin), priv_key_b58, 0);

	BN_bin2bn(&priv_key_bin[1], 32, dA_BN);
	
	BN_hex2bn(&dA_BN, Da_hex);
	
	if (eckey == NULL)
    {
        fprintf(stderr,"EC KEY new fail\n");
		return -1;
    }
	group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if (group == NULL)
    {
        fprintf(stderr,"Get group fail\n");
		return -1;
    }
	
	EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
	if(!EC_KEY_set_group(eckey, group))
	{
		fprintf(stderr,"Set group fail\n");
		return -1;
	}
	
	pub_key = EC_POINT_new(group);
	if(pub_key == NULL)
	{
		fprintf(stderr,"EC new point fail\n");
		return -1;
	}
	if (!EC_POINT_mul(group, pub_key, dA_BN, NULL, NULL, ctx))
	{
		fprintf(stderr,"EC mul fail\n");
		return -1;
	}
	
	printf("QA: ");
	//BN_print_fp(stdout, pub_key->x);	
	EC_POINT_point2bn(group, pub_key, POINT_CONVERSION_COMPRESSED, tmp, ctx);
	BN_print_fp(stdout, tmp);
	printf("\n");
	
	EC_KEY_set_private_key(eckey,dA_BN);
    EC_KEY_set_public_key(eckey,pub_key);
	// Second step: compute the ECDSA signature of a SHA-1 hash value using ECDSA_do_sign

	printf("dA: "); BN_print_fp(stdout, dA_BN); printf("\n");
	
	sig = malloc(ECDSA_size(eckey));
	if(sig==NULL)
	{
		fprintf(stderr,"Malloc fail\n");
		return -1;
	}
	
	if(ECDSA_sign(0, digest, 32, sig, &siglen, eckey) != 1)
	{
		fprintf(stderr,"ECDSA sign error\n");
		return -1;
	}
	
	printf("Siglen %d\n", siglen);
	for(i=0; i<siglen; i++)
		printf("%02x", sig[i]);
	
	printf("\n");
	printf("Verify %d\n",  ECDSA_verify(0, digest,
                        32, sig,
                        siglen, eckey));

	
	
	ecdsa_test(m);		
	
	bn32_from_bin(digest_bn, digest);
	
	ecdsa_sign(r_bn, s_bn, digest_bn);
	
	bn32_to_bin(r, r_bn);
	bn32_to_bin(s, s_bn);
	
	BN_bin2bn(r, 32, ecsig->r);
	BN_bin2bn(s, 32, ecsig->s);
	BN_print_fp(stdout, ecsig->r); printf("\n");
	BN_print_fp(stdout, ecsig->s); printf("\n");
	printf("\n");
	printf("Verify %d\n",  ECDSA_do_verify(digest,
                        32, ecsig, eckey));
}



Point* point_new(BIGNUM *x, BIGNUM *y)
{
	Point *p = malloc(sizeof(Point));
	if(p==NULL)
	{
		fprintf(stderr, "malloc error\n");
		exit(1);
	}
	p->x = x;
	p->y = y;
	p->at_infinity = false;
	return p;
}

Point* point_at_infinity()
{
	Point *p = point_new(NULL,NULL);
	p->at_infinity = true;
	return p;
}
//Point* point_add(Point *P, Point *Q, Curve *c_)


/*
Point* ec_point_mul_old(Point *P, BIGNUM *n, Curve *c)
{
	BIGNUM *lambda = BN_new();
	BIGNUM *tmp = BN_new();
	BIGNUM *tmp2 = BN_new();
	BIGNUM *tmp3 = BN_new();
	
	BIGNUM *xr = BN_new();
	BIGNUM *yr = BN_new();
	Point *p2 = (Point*) malloc(sizeof(Point));
	
	if(BN_is_zero(n)) return P;
	else
	{
		if(BN_is_odd(n))
		{
			// f(2P, n/2)
			
			// lambda = (3x^2 + b)/2y
			BN_lshift1(tmp,P->y);		
			BN_mod(tmp3, tmp, c->p, ctx);
			BN_mod_sqr(tmp, P->x, c->p, ctx);			
			BN_mul_word(tmp, 3);						
			BN_mod_inverse(tmp2, tmp3, c->p, ctx);
			BN_mod_mul(lambda, tmp, tmp2, c->p, ctx);
			
			// xr = lambda^2 - 2x
			BN_mod_sqr(tmp, lambda, c->p, ctx);
			BN_lshift1(tmp2, P->x);
			BN_mod(tmp3, tmp2, c->p, ctx);
			BN_mod_sub(xr, tmp, tmp3, c->p, ctx);
			
			// yr = lambda(x - xr) - y
			BN_mod_sub(tmp, P->x, xr, c->p, ctx);
			BN_mod_mul(tmp2, lambda, tmp, c->p, ctx);
			BN_mod_sub(yr, tmp2, P->y, c->p, ctx);
			
			p2->x=xr;
			p2->y=yr;
			
			BN_rshift1(tmp,n);
			//
			// TODO FREE MEMORY
			return ec_point_mul(p2, tmp, c);
		} else {
			// P + f(P, n-1)
			BN_mod_sub(tmp, n, BN_value_one(), c->p, ctx);
			p2 = ec_point_mul(P, tmp, c);
			
			// lambda = (yq-yp)/(xq-xp)
			BN_mod_sub(tmp, p2->y, P->y, c->p, ctx);
			BN_mod_sub(tmp2, p2->x, P->x, c->p, ctx);
			BN_mod_inverse(tmp3, tmp2, c->p, ctx);
			BN_mod_mul(lambda, tmp, tmp3, c->p, ctx);
			
			
			// xr = lambda^2 - xp - xq
			BN_mod_sqr(tmp, lambda, c->p, ctx);
			BN_mod_sub(tmp2, tmp, P->x, c->p, ctx);
			BN_mod_sub(xr, tmp2, p2->x, c->p, ctx);
			
			// yr = lambda(xp - xr) - yp
			BN_mod_sub(tmp, P->x, xr, c->p, ctx);
			BN_mod_mul(tmp2, lambda, tmp, c->p, ctx);
			BN_mod_sub(yr, tmp2, P->y, c->p, ctx);
			
			// TODO FREE MEMORY
			p2->x = xr;
			p2->y = yr;
			return p2;
		}
	}
}*/
