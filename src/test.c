#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include "base58.h"

const char priv_key_b58[] = "cSoZxDuKeR2TWRyQp8ZXAgPogL281Y786ZogzfmK13c1RBNRcmYS";

typedef struct
{
	BIGNUM *x;
	BIGNUM *y;
} Point;

typedef struct 
{
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
	Point G;
	G.x = BN_new();
	G.y = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *k = BN_new();
	BIGNUM *z = BN_new();
	BIGNUM *r = BN_new();
	BIGNUM *s = BN_new();	
		
	
	BIGNUM *tmp = BN_new();
	BIGNUM *tmp2 = BN_new();
	
	BN_hex2bn(&p, p_hex);
	BN_hex2bn(&b, b_hex);
	BN_hex2bn(&(G.x), Gx_hex);
	BN_hex2bn(&(G.y), Gy_hex);
	BN_hex2bn(&n, n_hex);
	mod = n;
	Point *curve_point, *point;
	c.b = b;
	c.p=p;
	
	point = ec_point_mul(&G, dA, &c);
	printf("QA x: ");
	BN_print_fp(stdout, point->x);	
	printf("QA y: ");
	BN_print_fp(stdout, point->y);	
	printf("\n");
	
	// 2. 
	BN_bin2bn(digest, digest_len, z);
	
	// 3. select random k
	BN_sub(tmp, n, BN_value_one()); //n-1
	BN_rand_range(k, tmp);
	
	// 4. (x1,y1) = k * G
	
	curve_point = ec_point_mul(&G, k, &c);
	
	
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

Point* ec_point_mul(Point *P, BIGNUM *n, Curve *c)
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
