#ifndef _ECDSA_H
#define _ECDSA_H

void ecdsa_test(bn8 m);
void ecdsa_sign(bn8 r, bn8 s, bn8 z);
void ec_point_mul(bn8 xr, bn8 yr, bn8 xp_, bn8 yp_, bn8 k);
void ec_point_mul_jacobian(bn8 xr, bn8 yr, bn8 xp_, bn8 yp_, bn8 k);

#endif