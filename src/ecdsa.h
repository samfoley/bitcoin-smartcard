#ifndef _ECDSA_H
#define _ECDSA_H

void ecdsa_test(bn32 m);
void ecdsa_sign(uint8_t *r, uint8_t *s, uint8_t *hash);
void ec_point_mul(bn32 xr, bn32 yr, bn32 xp_, bn32 yp_, bn32 k);
void ec_point_mul_jacobian(bn32 xr, bn32 yr, bn32 xp_, bn32 yp_, bn32 k);
void ecdsa_set_private_key(bn32 key);
void ecdsa_get_public_key(bn32 key);

#endif