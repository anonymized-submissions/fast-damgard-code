//
//  encrypt.h
//  Cramer-Shoup
//
//  Created by Rokia on 6/6/17.
//  Copyright © 2017 Rokia. All rights reserved.
//

#ifndef encrypt_h
#define encrypt_h

#include <stdio.h>
#include <gmp.h>
#include "keys.h"

void encrypt_(gmp_randstate_t generator,CipherT *cipher, publicK pk, Cgroup gr,mpz_t msg);
void enc1_(mpz_t k,gmp_randstate_t generator,CipherT *cipher, publicK pk, Cgroup gr,mpz_t msg);
void enc2_(mpz_t k,gmp_randstate_t generator,CipherT *cipher, publicK pk, Cgroup gr,mpz_t msg);
void enc3_(mpz_t k,gmp_randstate_t generator,CipherT *cipher, publicK pk, Cgroup gr,mpz_t msg);
void enc4_(mpz_t k,gmp_randstate_t generator,CipherT *cipher, publicK pk, Cgroup gr,mpz_t msg);
void encrypt_fast(gmp_randstate_t generator,CipherT_fast *cipher, publicK_fast pk, Cgroup_fast gr,mpz_t msg);
void enc1_fast(mpz_t r,gmp_randstate_t generator,CipherT_fast *cipher, publicK_fast pk, Cgroup_fast gr,mpz_t msg);
void enc2_fast(mpz_t r,gmp_randstate_t generator,CipherT_fast *cipher, publicK_fast pk, Cgroup_fast gr,mpz_t msg);
void enc3_fast(mpz_t r,gmp_randstate_t generator,CipherT_fast *cipher, publicK_fast pk, Cgroup_fast gr,mpz_t msg);
void enc4_fast(mpz_t r,gmp_randstate_t generator,CipherT_fast *cipher, publicK_fast pk, Cgroup_fast gr,mpz_t msg);
void encrypt_short(gmp_randstate_t generator,CipherT_short *cipher, publicK pk, Cgroup_fast gr,mpz_t msg);
void encrypt_fast_s(gmp_randstate_t generator,CipherT_short *cipher, publicK_fast pk, Cgroup_fast gr,mpz_t msg);
void encrypt_LCS(gmp_randstate_t generator,CipherT_LCS *cipher, publicK_LCS pk, Cgroup_LCS gr,mpz_t msg);
void encrypt_FLCS(gmp_randstate_t generator,CipherT_LCS *cipher, publicK_FLCS pk, Cgroup_fast gr,mpz_t msg);
void encrypt_FLCS_var(gmp_randstate_t generator,CipherT_LCS *cipher, publicK_FLCS pk, Cgroup_fast gr,mpz_t msg);
void encrypt_LCS_short(gmp_randstate_t generator,CipherT_LCS *cipher, publicK_LCS pk, Cgroup_LCS gr,mpz_t msg);
void encrypt_FLCS_v1(gmp_randstate_t generator,CipherT_LCS *cipher, publicK_FLCS pk, Cgroup_fast gr,mpz_t msg);
void encrypt_damgard(gmp_randstate_t generator,CipherT_short *cipher, publicK_damgard pk, Cgroup_fast gr,mpz_t msg);
void encrypt_damgard_fast(gmp_randstate_t generator,CipherT_short *cipher, publicK pk, Cgroup_fast gr,mpz_t msg);
void encrypt_LD(gmp_randstate_t generator,CipherT_LD *cipher, publicK_LD pk, Cgroup_fast gr,mpz_t msg);
void encrypt_LD_fast(gmp_randstate_t generator,CipherT_LD *cipher, publicK_LD_fast pk, Cgroup_fast gr,mpz_t msg);
#endif /* encrypt_h */
