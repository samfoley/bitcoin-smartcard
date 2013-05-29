#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <stdio.h>

#include "base58.h"

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
BIGNUM *dA = NULL;

ECDSA_SIG* ECDSA_test_sign(unsigned char *digest, int digest_len, unsigned char *sig, int *siglen);

Point* ec_point_mul(Point *P, BIGNUM *n, Curve *c);
Point* point_new(BIGNUM *x, BIGNUM *y);
Point* point_at_infinity();
Point *point_add(Point *P, Point *Q, Curve *c);
Point *point_double(Point *P, Curve *c);

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
	
	dA = BN_new();
	_blkmk_b58tobin(priv_key_bin, sizeof(priv_key_bin), priv_key_b58, 0);
	
	BN_bin2bn(&priv_key_bin[1], 32, dA);
	
	BN_hex2bn(&dA, Da_hex);
	
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
	if (!EC_POINT_mul(group, pub_key, dA, NULL, NULL, ctx))
	{
		fprintf(stderr,"EC mul fail\n");
		return -1;
	}
	
	printf("QA: ");
	//BN_print_fp(stdout, pub_key->x);	
	EC_POINT_point2bn(group, pub_key, POINT_CONVERSION_UNCOMPRESSED, tmp, ctx);
	BN_print_fp(stdout, tmp);
	printf("\n");
	
	EC_KEY_set_private_key(eckey,dA);
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

ECDSA_SIG* ECDSA_test_sign(unsigned char *digest, int digest_len, unsigned char *sig, int *siglen)
{
	Curve c;
	ECDSA_SIG *ecsig = ECDSA_SIG_new();
	
	BIGNUM *p = BN_new();
	BIGNUM *b = BN_new();
	//BIGNUM *G = BN_new();
	Point *G = point_new(BN_new(), BN_new());	
	BIGNUM *n = BN_new();
	BIGNUM *k = BN_new();
	BIGNUM *z = BN_new();
	BIGNUM *r = BN_new();
	BIGNUM *s = BN_new();	
		
	
	BIGNUM *tmp = BN_new();
	BIGNUM *tmp2 = BN_new();
	
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
	
	// EC Tests
	printf("\n\n");
	BIGNUM *m = BN_new();
	BN_hex2bn(&m, "AA5E28D6A97A2479A65527F7290311A3624D4CC0FA1578598EE3C2613BF99522");
	point = ec_point_mul(G, m, &c);
	printf("\nQm x: ");
	BN_print_fp(stdout, point->x);	
	printf("\nQm y: ");
	BN_print_fp(stdout, point->y);	
	printf("\n\n");
	
	// 2. 
	BN_bin2bn(digest, digest_len, z);
	
	// 3. select random k
	BN_sub(tmp, n, BN_value_one()); //n-1
	BN_rand_range(k, tmp);
	
	// 4. (x1,y1) = k * G
	
	curve_point = ec_point_mul(G, k, &c);
	
	
	// 5. r = x1 (mod n)
	BN_mod(r, curve_point->x, mod, ctx);
	
	// 6. s = k^-1(z + rdA) (mod n)
	BN_mod_mul(tmp, r, dA, mod, ctx);
	BN_mod_add(tmp2, z, tmp, mod, ctx);
	BN_mod_inverse(tmp, k, mod, ctx);
	BN_mod_mul(s, tmp, tmp2, mod, ctx);
	
	printf("r: ");
	BN_print_fp(stdout, r);
	printf("\ns: ");
	BN_print_fp(stdout, s);
	printf("\n");
	
	ecsig->r=r;
	ecsig->s=s;
	return ecsig;
}

Point* ec_point_mul(Point *P, BIGNUM *k, Curve *c)
{
	Point *Q = point_at_infinity();
	int i = 0;
	
	for(i=0; i<BN_num_bits(k); i++)
	{
		if(BN_is_bit_set(k,i))
		{
			Q = point_add(Q, P, c);
		}
		P = point_double(P, c);
	}
	
	return Q;
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

Point* point_add(Point *P, Point *Q, Curve *c)
{
	BIGNUM *lambda = BN_new();
	BIGNUM *tmp = BN_new();
	BIGNUM *tmp2 = BN_new();
	BIGNUM *tmp3 = BN_new();
	
	BIGNUM *xr = BN_new();
	BIGNUM *yr = BN_new();
	
	if(P->at_infinity) return Q;
	if(Q->at_infinity) return P;
	
	// lambda = (yq-yp)/(xq-xp)
	if (!BN_mod_sub(tmp, Q->y, P->y, c->p, ctx)) goto err; // yq-yp
	if (!BN_mod_sub(tmp2, Q->x, P->x, c->p, ctx)) goto err; // xq-xp
	if (!BN_mod_inverse(tmp3, tmp2, c->p, ctx)) goto err; // (xq-xp)^-1
	if (!BN_mod_mul(lambda, tmp, tmp3, c->p, ctx)) goto err; // (yq-yp)/(xq-xp)
	
	
	// xr = lambda^2 - xp - xq
	if (!BN_mod_sqr(tmp, lambda, c->p, ctx)) goto err; // lambda^2
	if (!BN_mod_sub(tmp2, tmp, P->x, c->p, ctx)) goto err; // lambda^2 - xp
	if (!BN_mod_sub(xr, tmp2, Q->x, c->p, ctx)) goto err; // lambda^2 - xp - xq
	
	// yr = lambda(xp - xr) - yp
	if (!BN_mod_sub(tmp, P->x, xr, c->p, ctx)) goto err; // xp - xr
	if (!BN_mod_mul(tmp2, lambda, tmp, c->p, ctx)) goto err; // lambda(xp-xr)
	if (!BN_mod_sub(yr, tmp2, P->y, c->p, ctx)) goto err; // lambda(xp-xr) - yp
		
	return point_new(xr, yr);	
	
	err:
	fprintf(stderr, "BN add error\n");
	exit(1);
	return NULL;
	
}

Point* point_double(Point *P, Curve *c)
{
	BIGNUM *lambda = BN_new();
	BIGNUM *tmp = BN_new();
	BIGNUM *tmp2 = BN_new();
	BIGNUM *tmp3 = BN_new();
	
	BIGNUM *xr = BN_new();
	BIGNUM *yr = BN_new();
	
	if(P->at_infinity) return P;
	
	
	// lambda = (3x^2 + a)/2y
	if (!BN_lshift1(tmp,P->y)) goto err; // 2yp		
	if (!BN_mod(tmp3, tmp, c->p, ctx)) goto err; // 2yp mod p
	if (!BN_mod_sqr(tmp2, P->x, c->p, ctx)) goto err; // xp^2		
	if (!BN_mul_word(tmp2, 3)) goto err; // 3xp^2
	if (!BN_mod(tmp, tmp2, c->p, ctx)) goto err; // 3xp^2 mod p
	if(!BN_mod_add(tmp2, tmp, c->a, c->p, ctx)) goto err; // 3xp^2+a
	if (!BN_mod_inverse(tmp, tmp3, c->p, ctx)) goto err; // (2yp)^-1
	if (!BN_mod_mul(lambda, tmp2, tmp, c->p, ctx)) goto err; // lambda = (3xp^2+a)(2yp)^-1
	
	// xr = lambda^2 - 2x
	if (!BN_mod_sqr(tmp, lambda, c->p, ctx)) goto err; // lambda^2
	if (!BN_lshift1(tmp2, P->x)) goto err; // 2xp
	if (!BN_mod(tmp3, tmp2, c->p, ctx)) goto err; // 2xp mod p
	if (!BN_mod_sub(xr, tmp, tmp3, c->p, ctx)) goto err; // lambda^2 - 2xp
	
	// yr = lambda(x - xr) - y
	if (!BN_mod_sub(tmp, P->x, xr, c->p, ctx)) goto err; // xp-xr
	if (!BN_mod_mul(tmp2, lambda, tmp, c->p, ctx)) goto err; // lambda(xp-xr)
	if (!BN_mod_sub(yr, tmp2, P->y, c->p, ctx)) goto err; // lambda(xp-xr) - yp
	
	return point_new(xr, yr);
	
	err:
	fprintf(stderr, "BN double error\n");
	exit(1);
	return NULL;	
}

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
}
