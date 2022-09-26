//
//  decrypt.h
//  Cramer-Shoup
//
//  Created by Rokia on 6/6/17.
//  Copyright © 2017 Rokia. All rights reserved.
//

#ifndef decrypt_h
#define decrypt_h

#include <stdio.h>
#include <gmp.h>
#include "keys.h"

void verif_(secretK sk, Cgroup gr, CipherT cipherT);
void decrypt_(mpz_t plainT, secretK sk, Cgroup gr, CipherT cipherT);
void decrypt_basic(mpz_t plainT, secretK sk, Cgroup gr, CipherT cipherT);
void verif1_variant(secretK_variant sk, Cgroup gr, CipherT cipherT);
void verif2_variant(secretK_variant sk, Cgroup gr, CipherT cipherT);
void decrypt_variant(mpz_t plainT, secretK_variant sk, Cgroup gr, CipherT cipherT);
void verif1_fast(secretK_fast sk, Cgroup_fast gr, CipherT_fast cipherT);
void verif2_fast(secretK_fast sk, Cgroup_fast gr, CipherT_fast cipherT);
void verif3_fast(secretK_fast sk, Cgroup_fast gr, CipherT_fast cipherT);
void verif4_fast(secretK_fast sk, Cgroup_fast gr, CipherT_fast cipherT);
void decrypt_fast(mpz_t plainT, secretK_fast sk, Cgroup_fast gr, CipherT_fast cipherT);
void verif3_opti_fast(mpz_t u1q,secretK_fast sk, Cgroup_fast gr, CipherT_fast cipherT);
void decrypt_opti(mpz_t u1q, mpz_t plainT, secretK_fast sk, Cgroup_fast gr, CipherT_fast cipherT);
void decrypt_short(mpz_t plainT, secretK_short sk, Cgroup_fast gr, CipherT_short cipherT);
void verif_short(mpz_t plainT, secretK_short sk, Cgroup_fast gr, CipherT_short cipherT);
void decrypt_fast_s(mpz_t plainT, secretK_short sk, Cgroup_fast gr, CipherT_short cipherT);
void verif_fast_s(mpz_t plainT, secretK_short sk, Cgroup_fast gr, CipherT_short cipherT);
void verif_LCS(secretK_LCS sk, Cgroup_LCS gr, CipherT_LCS cipherT);
void decrypt_LCS(mpz_t plainT, secretK_LCS sk, Cgroup_LCS gr, CipherT_LCS cipherT);
void verif_FLCS(secretK_FLCS sk, Cgroup_fast gr, CipherT_LCS cipherT);
void decrypt_FLCS(mpz_t plainT, secretK_FLCS sk, Cgroup_fast gr, CipherT_LCS cipherT);
void verif_FLCS_variant(mpz_t tmp_dec,secretK_FLCS sk, Cgroup_fast gr, CipherT_LCS cipherT);
void decrypt_FLCS_var(mpz_t tmp_dec,mpz_t plainT, secretK_FLCS sk, Cgroup_fast gr, CipherT_LCS cipherT);
void decrypt_LCS_short(mpz_t plainT, secretK_LCS_short sk, Cgroup_LCS gr, CipherT_LCS cipherT);
void verif_LCS_short(mpz_t plainT, secretK_LCS_short sk, Cgroup_LCS gr, CipherT_LCS cipherT);
void verif_FLCS_v1(secretK_FLCS_3 sk, Cgroup_fast gr, CipherT_LCS cipherT);
void decrypt_FLCS_v1(mpz_t plainT, secretK_FLCS_3 sk, Cgroup_fast gr, CipherT_LCS cipherT);
void verif_damgard(secretK_damgard sk, Cgroup_fast gr, CipherT_short cipherT);
void decrypt_damgard(mpz_t plainT, secretK_damgard sk, Cgroup_fast gr, CipherT_short cipherT);
void verif_damgard_fast(secretK_damgard sk, Cgroup_fast gr, CipherT_short cipherT);
void decrypt_damgard_fast(mpz_t plainT, secretK_damgard sk, Cgroup_fast gr, CipherT_short cipherT);
void verif_LD(secretK_LD sk, Cgroup_fast gr, CipherT_LD cipherT);
void decrypt_LD(mpz_t plainT, secretK_LD sk, Cgroup_fast gr, CipherT_LD cipherT);
void verif_LD_fast(secretK_LD sk, Cgroup_fast gr, CipherT_LD cipherT);
void decrypt_LD_fast(mpz_t plainT, secretK_LD sk, Cgroup_fast gr, CipherT_LD cipherT);
#endif /* decrypt_h */
