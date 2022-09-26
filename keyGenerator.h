#ifndef keyGenerator_h
#define keyGenerator_h

#include <stdio.h>
#include "keys.h"

void keyGenerator(gmp_randstate_t generator,Cgroup_fast *glo,secretK *sk,publicK *pk,Cgroup *g,unsigned int bitLengthK);
void keyGenerator_basic(gmp_randstate_t generator,Cgroup_fast *glo, secretK *sk,publicK *pk,Cgroup *g,unsigned int bitLengthK);
void keyGenerator_variant(gmp_randstate_t generator,Cgroup_fast *glo,secretK_variant *sk,publicK *pk,Cgroup *g,unsigned int bitLengthK);
void keyGenerator_fast(gmp_randstate_t generator,Cgroup_fast *glo,secretK_fast *sk,publicK_fast *pk,Cgroup_fast *g,unsigned int bitLengthK);
void keyGenerator_short(gmp_randstate_t generator,Cgroup_fast *glo, secretK_short *sk,publicK *pk,Cgroup_fast *g,unsigned int bitLengthK);
void keyGenerator_fast_s(gmp_randstate_t generator,Cgroup_fast *glo,secretK_short *sk,publicK_fast *pk,Cgroup_fast *g,unsigned int bitLengthK);
void keyGenerator_LCS(gmp_randstate_t generator,Cgroup_fast *glo, secretK_LCS *sk,publicK_LCS *pk,Cgroup_LCS *g,unsigned int bitLengthK);
void keyGenerator_FLCS(gmp_randstate_t generator,Cgroup_fast *glo, secretK_FLCS *sk,publicK_FLCS *pk,Cgroup_fast *g,unsigned int bitLengthK);
void keyGenerator_LCS_short(gmp_randstate_t generator,Cgroup_fast *glo, secretK_LCS_short *sk,publicK_LCS *pk,Cgroup_LCS *g,unsigned int bitLengthK);
void keyGenerator_FLCS_v1(gmp_randstate_t generator,Cgroup_fast *glo, secretK_FLCS_3 *sk,publicK_FLCS *pk,Cgroup_fast *g,unsigned int bitLengthK);
void keyGenerator_damgard(gmp_randstate_t generator,Cgroup_fast *glo, secretK_damgard *sk,publicK_damgard *pk,Cgroup_fast *g,unsigned int bitLengthK);
void keyGenerator_damgard_fast(gmp_randstate_t generator,Cgroup_fast *glo, secretK_damgard *sk,publicK *pk,Cgroup_fast *g,unsigned int bitLengthK);
void keyGenerator_LD(gmp_randstate_t generator,Cgroup_fast *glo, secretK_LD *sk,publicK_LD *pk,Cgroup_fast *g,unsigned int bitLengthK);
void keyGenerator_LD_fast(gmp_randstate_t generator,Cgroup_fast *glo, secretK_LD *sk,publicK_LD_fast *pk,Cgroup_fast *g,unsigned int bitLengthK);
#endif /* keyGenerator_h */
