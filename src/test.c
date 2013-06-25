#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include "base58.h"
#include "bignum8.h"

uint8_t bn8_buffer_1[BN8_SIZE] = { 0 };
uint8_t bn8_buffer_2[BN8_SIZE] = { 0 };
uint8_t bn8_buffer_3[BN8_SIZE] = { 0 };
uint8_t bn8_buffer_4[BN8_SIZE] = { 0 };
uint8_t bn8_buffer_r[BN8_SIZE*2] = { 0 };

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
const char Da_hex[] = "483ADA7726A344655DA4FBFC0E5508A8FD17B44BAD8554199C47D08FFB10D4B8";
const char n_hex[] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
int h = 1;
BN_CTX *ctx = NULL;
BIGNUM *mod = NULL;
BIGNUM *dA_BN = NULL;

ECDSA_SIG* ECDSA_test_sign(unsigned char *digest, int digest_len, unsigned char *sig, int *siglen);

Point* point_new(BIGNUM *x, BIGNUM *y);
Point* point_at_infinity();

void ec_point_mul(bn8 xr, bn8 yr, bn8 xp, bn8 yp, bn8 k);
void point_double(bn8 xr, bn8 yr, bn8 xp, bn8 yp);
void point_add(bn8 xr, bn8 y, bn8 xp, bn8 yp, bn8 xq, bn8 yq);

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
	ECDSA_SIG *ecsig = NULL;
    EC_POINT *pub_key = NULL;
	BIGNUM *tmp = BN_new();
	
	
	
	
	
	
	if ((ctx = BN_CTX_new()) == NULL)
	{
		fprintf(stderr,"BN_CTX fail\n");
        return -1;
	}	
	
	// test bn8_lshift
	bn8_buffer_1[BN8_SIZE-1] = 0xff;
	bn8_buffer_1[BN8_SIZE-1] = 0xba;
	bn8_lshift(bn8_buffer_1, 9);
	printf("lshift ");
	bn8_print(bn8_buffer_1);
	printf("\n\n");
	bn8_buffer_1[BN8_SIZE-1] = 0x00;
	
	// test bn8_add_shift
	printf("addshift\n\n");
	bn8_buffer_1[BN8_SIZE-1] = 1;
	bn8_buffer_1[BN8_SIZE-2] = 0xab;
	bn8_buffer_1[BN8_SIZE-3] = 0xff;
	bn8_add_shift(bn8_buffer_r, bn8_buffer_1, 4);
	bn8_add_shift(bn8_buffer_r, bn8_buffer_1, 32);
	
	bn8_buffer_2[BN8_SIZE-1] = 0xff;
	bn8_add_shift(bn8_buffer_r, bn8_buffer_2, 0);
	bn8_print(bn8_buffer_r); bn8_print(bn8_buffer_r+BN8_SIZE);
	printf("\n\n");
	
	// test rshift
	bn8_print(bn8_buffer_1); printf("\nrshift\n");
	bn8_rshift1(bn8_buffer_1, BN8_SIZE); 
	bn8_print(bn8_buffer_1); printf("\n");
	// test rshift
	printf("\nlshift\n");
	bn8_lshift1(bn8_buffer_1, BN8_SIZE); 
	bn8_print(bn8_buffer_1); printf("\n");
	// test 3x
	printf("3x\n");
	bn8_mul3(bn8_buffer_r, bn8_buffer_1, BN8_SIZE);
	bn8_printn(bn8_buffer_r, BN8_SIZE+1); printf("\n");
	
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
	EC_POINT_point2bn(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, tmp, ctx);
	BN_print_fp(stdout, tmp);
	printf("\n");
	
	EC_KEY_set_private_key(eckey,dA_BN);
    EC_KEY_set_public_key(eckey,pub_key);
	// Second step: compute the ECDSA signature of a SHA-1 hash value using ECDSA_do_sign

	
	
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
						
	ecsig = ECDSA_test_sign(digest, 32, sig, &siglen);
	
	printf("\n");
	printf("Verify %d\n",  ECDSA_do_verify(digest,
                        32, ecsig, eckey));
}

ECDSA_SIG* ECDSA_test_sign(unsigned char *z, int digest_len, unsigned char *sig, int *siglen)
{
	uint8_t Gx[BN8_SIZE];
	uint8_t Gy[BN8_SIZE];
	uint8_t x1[BN8_SIZE];
	uint8_t y1[BN8_SIZE];
	uint8_t k[BN8_SIZE];
	uint8_t dA[BN8_SIZE];
	uint8_t r_[BN8_SIZE+2];
	uint8_t s_[BN8_SIZE+2];
	
	uint8_t dd[BN8_SIZE*2];
	uint8_t tmp[BN8_SIZE+2] = {0};
	uint8_t tmp2[BN8_SIZE+2] = {0};
	
	bn8 r = r_+2;
	bn8 s = s_+2;
	
	// REMOVE THESE!
	BIGNUM *tmpBN = BN_new();
	BIGNUM *tmp2BN = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *kBN = BN_new();
	ECDSA_SIG *ecsig = ECDSA_SIG_new();
	
	/*
	Curve c;
	
	
	BIGNUM *p = BN_new();
	BIGNUM *b = BN_new();
	//BIGNUM *G = BN_new();
	Point *G = point_new(BN_new(), BN_new());	
	BIGNUM *n = BN_new();
	BIGNUM *kBN = BN_new();
	BIGNUM *z = BN_new();
	BIGNUM *r = BN_new();
	BIGNUM *s = BN_new();	
		
	
	BIGNUM *tmp = BN_new();
	BIGNUM *tmp2 = BN_new();
	BIGNUM *tmp3 = BN_new();
	
	BN_hex2bn(&p, p_hex);
	BN_hex2bn(&b, b_hex);
	BN_hex2bn(&(G->x), Gx_hex);
	BN_hex2bn(&(G->y), Gy_hex);
	BN_hex2bn(&n, n_hex);
	mod = n;
	Point *curve_point, *point;
	c.b = b;
	c.p=p;
	c.a = BN_new();
	BN_zero(c.a);
	
	
	
	// 2. 
	BN_bin2bn(digest, digest_len, z);
	*/
	
	
	
	BN_hex2bn(&tmpBN, Gx_hex);
	bn8_from_bn(Gx, tmpBN);
	BN_hex2bn(&tmpBN, Gy_hex);
	bn8_from_bn(Gy, tmpBN);
	
	// EC Tests
	printf("\n\n");
	BIGNUM *mBN = BN_new();
	BN_hex2bn(&mBN, "AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522");
	
	bn8_from_bn(tmp, mBN);
	
	ec_point_mul(x1, y1, Gx, Gy, tmp);
	printf("\nQm x: ");
	bn8_print(x1);
	printf("\nQm y: ");
	bn8_print(y1);
	printf("\n\n");
	
	bn8_from_bn(dA, dA_BN);
	
	// 3. select random k
	BN_hex2bn(&n, n_hex);
	BN_sub(tmpBN, n, BN_value_one()); //n-1
	BN_rand_range(kBN, tmpBN);
	bn8_from_bn(k, kBN);
	
	// 4. (x1,y1) = k * G			
	ec_point_mul(x1, y1, Gx, Gy, k);
	
	// 5. r = x1 (mod n)	
	bn8_copy(r, x1, BN8_SIZE);
	bn8_mod(r, bn8_get_n(), BN8_SIZE);
	
	// 6. s = k^-1(z + rdA) (mod n)	
	bn8_mul(dd, r, dA, BN8_SIZE, BN8_SIZE); // r*dA
	bn8_barrett_reduction_n(tmp, dd); // r*dA (mod n)
	bn8_add_n(tmp+1, z, BN8_SIZE+1); // z + r*dA
	bn8_mod(tmp+1, bn8_get_n(), BN8_SIZE+1); // (z + rdA) (mod n)
	
	bn8_invert(tmp2, k, bn8_get_n()); // k^-1
	bn8_mul(dd, tmp+2, tmp2+2, BN8_SIZE, BN8_SIZE); // k^-1(z + rdA) (mod n)
	bn8_barrett_reduction_n(s_, dd);
	
	
	printf("r: ");
	bn8_print(r);
	printf("\ns: ");
	bn8_print(s);
	printf("\n");
	
	BN_bin2bn(r, BN8_SIZE, ecsig->r);
	BN_bin2bn(s, BN8_SIZE, ecsig->s);
	
	return ecsig;
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

void point_add(bn8 xr, bn8 yr, bn8 xp, bn8 yp, bn8 xq, bn8 yq)
{
/*
	BIGNUM *lambdaBN = BN_new();
	BIGNUM *tmp = BN_new();
	BIGNUM *tmp2 = BN_new();
	BIGNUM *tmp3 = BN_new();
	
	BIGNUM *xrBN = BN_new();
	BIGNUM *yrBN = BN_new();
	
	uint8_t xq[BN8_SIZE];
	uint8_t yq[BN8_SIZE];
	uint8_t xp[BN8_SIZE];
	uint8_t yp[BN8_SIZE];
	
	uint8_t xr[BN8_SIZE];
	uint8_t yr[BN8_SIZE];*/
	
	uint8_t a[BN8_SIZE];
	uint8_t b[BN8_SIZE];
	uint8_t c[BN8_SIZE];
	uint8_t dd[BN8_SIZE*2];
	uint8_t r[BN8_SIZE+2];
	uint8_t lambda[BN8_SIZE];
	
//!	if(P->at_infinity) return Q;
//!	if(Q->at_infinity) return P;
	/*
	// lambda = (yq-yp)/(xq-xp)
	//if (!BN_mod_sub(tmp, Q->y, P->y, c->p, ctx)) goto err; // yq-yp
	bn8_mod_sub(tmp, Q->y, P->y, c_->p, ctx);
	//if (!BN_mod_sub(tmp2, Q->x, P->x, c->p, ctx)) goto err; // xq-xp
	bn8_mod_sub(tmp2, Q->x, P->x, c_->p, ctx);
	//if (!BN_mod_inverse(tmp3, tmp2, c_p, ctx)) goto err; // (xq-xp)^-1
	bn8_mod_inverse(tmp3, tmp2, c_->p, ctx);
	bn8_mod_mulP(lambdaBN, tmp, tmp3, c_->p, ctx);
	//if (!BN_mod_mul(lambdaBN, tmp, tmp3, c->p, ctx)) goto err; // (yq-yp)/(xq-xp)
		
	
	// xr = lambdaBN^2 - xp - xq
	//if (!BN_mod_sqr(tmp, lambdaBN, c_->p, ctx)) goto err; // lambdaBN^2
	bn8_mod_mulP(tmp, lambdaBN, lambdaBN, c_->p, ctx);
	//if (!BN_mod_sub(tmp2, tmp, P->x, c_->p, ctx)) goto err; // lambdaBN^2 - xp
	bn8_mod_sub(tmp2, tmp, P->x, c_->p, ctx);
	//if (!BN_mod_sub(xr, tmp2, Q->x, c_->p, ctx)) goto err; // lambdaBN^2 - xp - xq
	bn8_mod_sub(xrBN, tmp2, Q->x, c_->p, ctx);
	
	// yr = lambdaBN(xp - xr) - yp
	//if (!BN_mod_sub(tmp, P->x, xr, c_->p, ctx)) goto err; // xp - xr
	bn8_mod_sub(tmp, P->x, xrBN, c_->p, ctx);
	//if (!BN_mod_mul(tmp2, lambdaBN, tmp, c_->p, ctx)) goto err; // lambdaBN(xp-xr)
	bn8_mod_mulP(tmp2, lambdaBN, tmp, c_->p, ctx);
	//if (!BN_mod_sub(yr, tmp2, P->y, c_->p, ctx)) goto err; // lambdaBN(xp-xr) - yp
	bn8_mod_sub(yrBN, tmp2, P->y, c_->p, ctx);
	
	*/
	/*bn8_from_bn(xp, P->x);
	bn8_from_bn(yp, P->y);
	bn8_from_bn(xq, Q->x);
	bn8_from_bn(yq, Q->y);*/
	
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
	
	/*
	BN_bin2bn(xr, BN8_SIZE, xrBN);
	BN_bin2bn(yr, BN8_SIZE, yrBN);
	
	return point_new(xrBN, yrBN);*/
	
	// BN helper functions implementation
	/*
	
		
	return point_new(xr, yr);	
	
	err:
	fprintf(stderr, "BN add error\n");
	exit(1);
	return NULL;*/
	
}

//Point* point_double(Point *P, Curve *c_)

void point_double(bn8 xr, bn8 yr, bn8 xp, bn8 yp)
{
/*	BIGNUM *lambdaBN = BN_new();
	BIGNUM *tmp = BN_new();
	BIGNUM *tmp2 = BN_new();
	BIGNUM *tmp3 = BN_new();
	
	BIGNUM *xrBN = BN_new();
	BIGNUM *yrBN = BN_new();
		
	uint8_t xp[BN8_SIZE];
	uint8_t yp[BN8_SIZE];
	
	uint8_t xr[BN8_SIZE];
	uint8_t yr[BN8_SIZE];*/
	
	uint8_t a[BN8_SIZE];
	uint8_t b[BN8_SIZE];
	uint8_t c[BN8_SIZE];
	uint8_t dd[BN8_SIZE*2];
	uint8_t r[BN8_SIZE+2];
	uint8_t lambda[BN8_SIZE];
	
//!	if(P->at_infinity) return P;
	
	
	/*bn8_from_bn(xp, P->x);
	bn8_from_bn(yp, P->y);	*/
	
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
	
	/*BN_bin2bn(xr, BN8_SIZE, xrBN);
	BN_bin2bn(yr, BN8_SIZE, yrBN);	
	return point_new(xrBN, yrBN);*/
	
	// BN helper implementation
	/*
	// lambda = (3x^2 + a)/2y
	if (!BN_lshift1(tmp,P->y)) goto err; // 2yp		
	//bn8_lshift1(tmp,P->y)
	if (!BN_mod(tmp3, tmp, c->p, ctx)) goto err; // 2yp mod p
	//bn8_mod(tmp3, tmp, c->p, ctx);
	//if (!BN_mod_sqr(tmp2, P->x, c->p, ctx)) goto err; // xp^2		
	bn8_mod_mulP(tmp2, P->x, P->x, c->p, ctx);
	if (!BN_mul_word(tmp2, 3)) goto err; // 3xp^2
	if (!BN_mod(tmp, tmp2, c->p, ctx)) goto err; // 3xp^2 mod p
	//if(!BN_mod_add(tmp2, tmp, c->a, c->p, ctx)) goto err; // 3xp^2+a
	bn8_mod_add(tmp2, tmp, c->a, c->p, ctx);
	//if (!BN_mod_inverse(tmp, tmp3, c->p, ctx)) goto err; // (2yp)^-1
	bn8_mod_inverse(tmp, tmp3, c->p, ctx);
	//if (!BN_mod_mul(lambda, tmp2, tmp, c->p, ctx)) goto err; // lambda = (3xp^2+a)(2yp)^-1
	bn8_mod_mulP(lambda, tmp2, tmp, c->p, ctx);
	
	// xr = lambda^2 - 2x
	if (!BN_mod_sqr(tmp, lambda, c->p, ctx)) goto err; // lambda^2
	if (!BN_lshift1(tmp2, P->x)) goto err; // 2xp
	if (!BN_mod(tmp3, tmp2, c->p, ctx)) goto err; // 2xp mod p
	//if (!BN_mod_sub(xr, tmp, tmp3, c->p, ctx)) goto err; // lambda^2 - 2xp
	bn8_mod_sub(xr, tmp, tmp3, c->p, ctx);
	
	// yr = lambda(x - xr) - y
	//if (!BN_mod_sub(tmp, P->x, xr, c->p, ctx)) goto err; // xp-xr
	bn8_mod_sub(tmp, P->x, xr, c->p, ctx);
	//if (!BN_mod_mul(tmp2, lambda, tmp, c->p, ctx)) goto err; // lambda(xp-xr)
	bn8_mod_mulP(tmp2, lambda, tmp, c->p, ctx);
	//if (!BN_mod_sub(yr, tmp2, P->y, c->p, ctx)) goto err; // lambda(xp-xr) - yp
	bn8_mod_sub(yr, tmp2, P->y, c->p, ctx);
	*/
	err: return;	
}
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
