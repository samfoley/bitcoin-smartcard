#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include "base58.h"

int main()
{
	int        ret;
	ECDSA_SIG *sig;
	EC_KEY    *eckey = EC_KEY_new();
	EC_GROUP *group     = NULL;
	unsigned char digest[32] = { 0 };
	
	if (eckey == NULL)
    {
        /* error */
    }
	group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if (group == NULL)
    {
        /* error */
    }
	
	EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
	if(!EC_KEY_set_group(eckey, group))
	{
		// error
	}
	
	if (!EC_KEY_generate_key(eckey))
    {
        /* error */
    }
	// Second step: compute the ECDSA signature of a SHA-1 hash value using ECDSA_do_sign

	sig = ECDSA_do_sign(digest, 20, eckey);
	if (sig == NULL)
    {
     /* error */
    }
	
	printf("r: ");
	BN_print_fp(stdout, sig->r);
	printf("\ns: ");
	BN_print_fp(stdout, sig->s);
	printf("\n");
}