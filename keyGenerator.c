#include "keyGenerator.h"
#include "RandomGenerator.h"
#include "primitiveRoot.h"
#include "keys.h"
#include <gmp.h>

//original CS: sk=(x1,x2,y1,y2,z1,z2)
void keyGenerator(gmp_randstate_t generator,Cgroup_fast *glo, secretK *sk,publicK *pk,Cgroup *g,unsigned int bitLengthK)
{
    mpz_t c1, c2, d1, d2,h1,h2;
    mpz_inits(c1, c2, d1, d2,h1,h2, NULL);
    //description of the group
    //glo is the group computed in main. Prime p is the same for all keygen
    mpz_set(g->p,glo->p);
    primitiveRoot_g_fast(generator,g->p,g->g1);
    primitiveRoot_g_fast(generator,g->p,g->g2);
    mpz_sub_ui(g->q,g->p,1);

    //secret key
    //function generate in RandomGenerator.c
    generate(generator,sk->x1,g->p,bitLengthK, 0);
    generate(generator,sk->x2,g->p,bitLengthK, 0);
    generate(generator,sk->y1,g->p,bitLengthK, 0);
    generate(generator,sk->y2,g->p,bitLengthK, 0);
    generate(generator,sk->z1,g->p,bitLengthK, 0);
    generate(generator,sk->z2,g->p,bitLengthK, 0);

    //public key
    mpz_powm(c1,g->g1,sk->x1,g->p);
    mpz_powm(c2,g->g2,sk->x2,g->p);
    mpz_mul(pk->c,c1,c2);
    mpz_mod(pk->c, pk->c, g->p);

    mpz_powm(d1,g->g1,sk->y1,g->p);
    mpz_powm(d2,g->g2,sk->y2,g->p);
    mpz_mul(pk->d,d1,d2);
    mpz_mod(pk->d, pk->d, g->p);

    mpz_powm(h1,g->g1,sk->z1,g->p);
    mpz_powm(h2,g->g2,sk->z2,g->p);
    mpz_mul(pk->h,h1,h2);
    mpz_mod(pk->h, pk->h, g->p);


    mpz_clears(c1, c2, d1, d2,h1,h2, NULL);
}

//basic CS: sk=(x1,x2,y1,y2,z)
void keyGenerator_basic(gmp_randstate_t generator,Cgroup_fast *glo, secretK *sk,publicK *pk,Cgroup *g,unsigned int bitLengthK)
{
    mpz_t c1, c2, d1, d2;
    mpz_inits(c1, c2, d1, d2, NULL);
    //description of the group
    //prime p
    mpz_set(g->p,glo->p);
    //generator
    primitiveRoot_g_fast(generator,g->p,g->g1);
    primitiveRoot_g_fast(generator,g->p,g->g2);
    mpz_sub_ui(g->q,g->p,1);

    //secret key
    generate(generator,sk->x1,g->p,bitLengthK, 0);
    generate(generator,sk->x2,g->p,bitLengthK, 0);
    generate(generator,sk->y1,g->p,bitLengthK, 0);
    generate(generator,sk->y2,g->p,bitLengthK, 0);
    generate(generator,sk->z1,g->p,bitLengthK, 0);

    //public key
    mpz_powm(c1,g->g1,sk->x1,g->p);
    mpz_powm(c2,g->g2,sk->x2,g->p);
    mpz_mul(pk->c,c1,c2);
    mpz_mod(pk->c, pk->c, g->p);

    mpz_powm(d1,g->g1,sk->y1,g->p);
    mpz_powm(d2,g->g2,sk->y2,g->p);
    mpz_mul(pk->d,d1,d2);
    mpz_mod(pk->d, pk->d, g->p);

    mpz_powm(pk->h,g->g1,sk->z1,g->p);

    mpz_clears(c1, c2, d1, d2, NULL);
}

// variant CS : sk=(w,x,y,z)
void keyGenerator_variant(gmp_randstate_t generator,Cgroup_fast *glo, secretK_variant *sk,publicK *pk,Cgroup *g,unsigned int bitLengthK)
{

    //description of the group
    mpz_set(g->p,glo->p);
    //generator
    primitiveRoot_g_fast(generator,g->p,g->g1);
    mpz_sub_ui(g->q,g->p,1);


    //secret key
    generate(generator,sk->x,g->p,bitLengthK, 0);
    generate(generator,sk->y,g->p,bitLengthK, 0);
    generate(generator,sk->z,g->p,bitLengthK, 0);
    generate(generator,sk->w,g->p,bitLengthK, 0);
    //public key
    mpz_powm(g->g2,g->g1,sk->w,g->p);
    mpz_powm(pk->c,g->g1,sk->x,g->p);
    mpz_powm(pk->d,g->g1,sk->y,g->p);
    mpz_powm(pk->h,g->g1,sk->z,g->p);

}

void keyGenerator_fast(gmp_randstate_t generator,Cgroup_fast *glo,secretK_fast *sk,publicK_fast *pk,Cgroup_fast *g,unsigned int bitLengthK)
{
    mpz_t k,v1,v2,v3,v4;
    mpz_inits(k,v1,v2,v3,v4,NULL);
    //description of the group
    mpz_set(g->p,glo->p);
    //generator
    primitiveRoot_g_fast(generator,g->p,g->gen1);
    mpz_sub_ui(g->q,g->p,1);

    //secret key
    generate(generator,sk->x,g->p,bitLengthK, 0);
    generate(generator,sk->y,g->p,bitLengthK, 0);
    generate(generator,k,g->p,bitLengthK, 0);//k is not in the secret key
    generate(generator,sk->quo,g->p,bitLengthK, 4);//from half space

    //generate s and t such that kd=qs+t

    mpz_mul(v1,g->q,k);
    mpz_tdiv_qr(sk->s,sk->t,v1,sk->quo);

    //public key
    mpz_mod(sk->s,sk->s,g->q);
    mpz_powm(pk->g1,g->gen1,sk->s,g->p);
    //c=g^(sx)
    mpz_mul(v1,sk->s,sk->x);
    mpz_mod(v1,v1,g->q);
    mpz_powm(pk->c,g->gen1,v1,g->p);
    //d=g^(sy)
    mpz_mul(v1,sk->s,sk->y);
    mpz_mod(v1,v1,g->q);
    mpz_powm(pk->d,g->gen1,v1,g->p);
    //h=g^t
    mpz_powm(pk->h,g->gen1,sk->t,g->p);

    mpz_clears(v1,k,v2,v3,v4,NULL);

}


void keyGenerator_short(gmp_randstate_t generator,Cgroup_fast *glo, secretK_short *sk,publicK *pk,Cgroup_fast *g,unsigned int bitLengthK)
{
    mpz_t c1, c2, d1, d2;
    mpz_inits(c1, c2, d1, d2, NULL);
    //description of the group
    //glo is the group computed in main. Prime p is the same for all keygen
    mpz_set(g->p,glo->p);
    primitiveRoot_g_fast(generator,g->p,g->gen1);
    mpz_sub_ui(g->q,g->p,1);

    //secret key
    //function generate in RandomGenerator.c
    generate(generator,sk->s,g->p,bitLengthK, 0);
    generate(generator,sk->a,g->p,bitLengthK, 0);
    generate(generator,sk->b,g->p,bitLengthK, 0);
    generate(generator,sk->ap,g->p,bitLengthK, 0);
    generate(generator,sk->bp,g->p,bitLengthK, 0);

    //public key
    mpz_powm(pk->h,g->gen1,sk->s,g->p);

    mpz_powm(c1,g->gen1,sk->a,g->p);
    mpz_powm(c2,pk->h,sk->b,g->p);
    mpz_mul(pk->c,c1,c2);
    mpz_mod(pk->c, pk->c, g->p);

    mpz_powm(d1,g->gen1,sk->ap,g->p);
    mpz_powm(d2,pk->h,sk->bp,g->p);
    mpz_mul(pk->d,d1,d2);
    mpz_mod(pk->d, pk->d, g->p);


    mpz_clears(c1, c2, d1, d2, NULL);
}

//short version with fast modif
void keyGenerator_fast_s(gmp_randstate_t generator,Cgroup_fast *glo,secretK_short *sk,publicK_fast *pk,Cgroup_fast *g,unsigned int bitLengthK)
{
    mpz_t k,v1,v2,v3,v4;
    mpz_inits(k,v1,v2,v3,v4,NULL);
    //description of the group
    mpz_set(g->p,glo->p);
    //generator
    primitiveRoot_g_fast(generator,g->p,g->gen1);
    mpz_sub_ui(g->q,g->p,1);

    //secret key
    generate(generator,sk->a,g->p,bitLengthK, 0);
    generate(generator,sk->ap,g->p,bitLengthK, 0);
    generate(generator,sk->b,g->p,bitLengthK, 0);
    generate(generator,sk->bp,g->p,bitLengthK, 0);
    generate(generator,k,g->p,bitLengthK, 0);//k is not in the secret key
    generate(generator,sk->s,g->p,bitLengthK, 4);//here s=q;from half space

    //generate s and t such that kd=qs+t

    mpz_mul(v1,g->q,k);
    mpz_tdiv_qr(v2,v3,v1,sk->s);//v2=s and v3=t

    //public key
    mpz_mod(v2,v2,g->q);
    mpz_powm(pk->g1,g->gen1,v2,g->p);
    //h=g^t
    mpz_powm(pk->h,g->gen1,v3,g->p);
    //c=g^(sa)*h^b
    mpz_mul(v1,v2,sk->a);
    mpz_mod(v1,v1,g->q);
    mpz_powm(v1,g->gen1,v1,g->p);
    mpz_powm(v4,pk->h,sk->b,g->p);
    mpz_mul(pk->c,v1,v4);
    mpz_mod(pk->c,pk->c,g->p);
    //d=g^(sap)*h^bp
    mpz_mul(v1,v2,sk->ap);
    mpz_mod(v1,v1,g->q);
    mpz_powm(v1,g->gen1,v1,g->p);
    mpz_powm(v4,pk->h,sk->bp,g->p);
    mpz_mul(pk->d,v1,v4);
    mpz_mod(pk->d,pk->d,g->p);


    mpz_clears(v1,k,v2,v3,v4,NULL);

}

//LCS
void keyGenerator_LCS(gmp_randstate_t generator,Cgroup_fast *glo, secretK_LCS *sk,publicK_LCS *pk,Cgroup_LCS *g,unsigned int bitLengthK)
{
    mpz_t c1, c2;
    mpz_inits(c1, c2, NULL);
    //description of the group
    //glo is the group computed in main. Prime p is the same for all keygen
    mpz_set(g->p,glo->p);
    //generator
    primitiveRoot_g_fast(generator,g->p,g->g1);
    primitiveRoot_g_fast(generator,g->p,g->g2);
    primitiveRoot_g_fast(generator,g->p,g->g3);
    mpz_sub_ui(g->q,g->p,1);

    //secret key
    //function generate in RandomGenerator.c
    generate(generator,sk->x1,g->p,bitLengthK, 0);
    generate(generator,sk->x2,g->p,bitLengthK, 0);
    generate(generator,sk->x3,g->p,bitLengthK, 0);
    generate(generator,sk->y1,g->p,bitLengthK, 0);
    generate(generator,sk->y2,g->p,bitLengthK, 0);
    generate(generator,sk->y3,g->p,bitLengthK, 0);
    generate(generator,sk->z1,g->p,bitLengthK, 0);
    generate(generator,sk->z2,g->p,bitLengthK, 0);
    generate(generator,sk->z3,g->p,bitLengthK, 0);

    //public key
    //c1
    mpz_powm(c1,g->g1,sk->x1,g->p);
    mpz_powm(c2,g->g3,sk->x3,g->p);
    mpz_mul(pk->c1,c1,c2);
    mpz_mod(pk->c1, pk->c1, g->p);
    //c2
    mpz_powm(c1,g->g2,sk->x2,g->p);
    mpz_mul(pk->c2,c1,c2);
    mpz_mod(pk->c2, pk->c2, g->p);


    //d1
    mpz_powm(c1,g->g1,sk->y1,g->p);
    mpz_powm(c2,g->g3,sk->y3,g->p);
    mpz_mul(pk->d1,c1,c2);
    mpz_mod(pk->d1, pk->d1, g->p);
    //d2
    mpz_powm(c1,g->g2,sk->y2,g->p);
    mpz_mul(pk->d2,c1,c2);
    mpz_mod(pk->d2, pk->d2, g->p);

    //h1
    mpz_powm(c1,g->g1,sk->z1,g->p);
    mpz_powm(c2,g->g3,sk->z3,g->p);
    mpz_mul(pk->h1,c1,c2);
    mpz_mod(pk->h1, pk->h1, g->p);
    //h2
    mpz_powm(c1,g->g2,sk->z2,g->p);
    mpz_mul(pk->h2,c1,c2);
    mpz_mod(pk->h2, pk->h2, g->p);


    mpz_clears(c1, c2, NULL);
}


//Fast LCS
void keyGenerator_FLCS(gmp_randstate_t generator,Cgroup_fast *glo, secretK_FLCS *sk,publicK_FLCS *pk,Cgroup_fast *g,unsigned int bitLengthK)
{
    mpz_t s1,s2,v1,v2,k1,k2;
    mpz_inits(s1,s2,v1,v2,k1,k2, NULL);
    //description of the group
    //glo is the group computed in main. Prime p is the same for all keygen
    mpz_set(g->p,glo->p);
    //generator
    primitiveRoot_g_fast(generator,g->p,g->gen1);
    mpz_sub_ui(g->q,g->p,1);

    //secret key
    //function generate in RandomGenerator.c
    generate(generator,sk->x1,g->p,bitLengthK, 0);
    generate(generator,sk->x2,g->p,bitLengthK, 0);
    generate(generator,sk->y1,g->p,bitLengthK, 0);
    generate(generator,sk->y2,g->p,bitLengthK, 0);
    generate(generator,k1,g->p,bitLengthK, 0);
    generate(generator,k2,g->p,bitLengthK, 0);

    //secret key
    generate(generator,sk->q1,g->p,bitLengthK, 4);//from half space
    generate(generator,sk->q2,g->p,bitLengthK, 4);//from half space

    //generate s and t such that kd=qs+t

    mpz_mul(v1,g->q,k1);
    mpz_tdiv_qr(s1,sk->t1,v1,sk->q1);
    mpz_mul(v2,g->q,k2);
    mpz_tdiv_qr(s2,sk->t2,v2,sk->q2);

    mpz_mod(s1,s1,g->q);
    mpz_mod(s2,s2,g->q);

    //public key
    mpz_powm(pk->g1,g->gen1,s1,g->p);//g1
    mpz_powm(pk->g2,g->gen1,s2,g->p);//g2
    mpz_set(pk->g3,g->gen1);//g3
    //c1
    mpz_powm(pk->c1,pk->g1,sk->x1,g->p);
    //c2
    mpz_powm(pk->c2,pk->g2,sk->x2,g->p);

    //d1
    mpz_powm(pk->d1,pk->g1,sk->y1,g->p);
    //d2
    mpz_powm(pk->d2,pk->g2,sk->y2,g->p);

    //h1
    mpz_powm(pk->h1,pk->g3,sk->t1,g->p);
    //h2
    mpz_powm(pk->h2,pk->g3,sk->t2,g->p);


    mpz_clears(s1,s2,v1,v2,k1,k2, NULL);
}


//SHORT LCS
void keyGenerator_LCS_short(gmp_randstate_t generator,Cgroup_fast *glo, secretK_LCS_short *sk,publicK_LCS *pk,Cgroup_LCS *g,unsigned int bitLengthK)
{
    mpz_t v1,v2;
    mpz_inits(v1,v2, NULL);
    //description of the group
    //glo is the group computed in main. Prime p is the same for all keygen
    mpz_set(g->p,glo->p);
    //generator
    primitiveRoot_g_fast(generator,g->p,g->g1);
    primitiveRoot_g_fast(generator,g->p,g->g2);
    primitiveRoot_g_fast(generator,g->p,g->g3);
    mpz_sub_ui(g->q,g->p,1);

    //secret key
    //function generate in RandomGenerator.c
    generate(generator,sk->s1,g->p,bitLengthK, 0);
    generate(generator,sk->s2,g->p,bitLengthK, 0);
    generate(generator,sk->a1,g->p,bitLengthK, 0);
    generate(generator,sk->b1,g->p,bitLengthK, 0);
    generate(generator,sk->ap1,g->p,bitLengthK, 0);
    generate(generator,sk->bp1,g->p,bitLengthK, 0);
    generate(generator,sk->a2,g->p,bitLengthK, 0);
    generate(generator,sk->b2,g->p,bitLengthK, 0);
    generate(generator,sk->ap2,g->p,bitLengthK, 0);
    generate(generator,sk->bp2,g->p,bitLengthK, 0);

    //PK
    //h1=g1^s1 ; h2=g2^s2
    mpz_powm(pk->h1,g->g1,sk->s1,g->p);
    mpz_powm(pk->h2,g->g2,sk->s2,g->p);

    //c1
    mpz_powm(v1,g->g1,sk->a1,g->p);
    mpz_powm(v2,pk->h1,sk->b1,g->p);
    mpz_mul(pk->c1,v1,v2);
    mpz_mod(pk->c1,pk->c1,g->p);
    //c2
    mpz_powm(v1,g->g2,sk->a2,g->p);
    mpz_powm(v2,pk->h2,sk->b2,g->p);
    mpz_mul(pk->c2,v1,v2);
    mpz_mod(pk->c2,pk->c2,g->p);

    //d1
    mpz_powm(v1,g->g1,sk->ap1,g->p);
    mpz_powm(v2,pk->h1,sk->bp1,g->p);
    mpz_mul(pk->d1,v1,v2);
    mpz_mod(pk->d1,pk->d1,g->p);
    //d2
    mpz_powm(v1,g->g2,sk->ap2,g->p);
    mpz_powm(v2,pk->h2,sk->bp2,g->p);
    mpz_mul(pk->d2,v1,v2);
    mpz_mod(pk->d2,pk->d2,g->p);


    mpz_clears(v1,v2, NULL);
}


//Fast LCS other version pascal
void keyGenerator_FLCS_v1(gmp_randstate_t generator,Cgroup_fast *glo, secretK_FLCS_3 *sk,publicK_FLCS *pk,Cgroup_fast *g,unsigned int bitLengthK)
{
    mpz_t v1,v2,k1,k2,k3;
    mpz_inits(v1,v2,k1,k2,k3, NULL);
    //description of the group
    //glo is the group computed in main. Prime p is the same for all keygen
    mpz_set(g->p,glo->p);
    //generator
    primitiveRoot_g_fast(generator,g->p,g->gen1);
    mpz_sub_ui(g->q,g->p,1);

    //secret key
    //function generate in RandomGenerator.c
    generate(generator,sk->x1,g->p,bitLengthK, 0);
    generate(generator,sk->x2,g->p,bitLengthK, 0);
    generate(generator,sk->x3,g->p,bitLengthK, 0);
    generate(generator,sk->y1,g->p,bitLengthK, 0);
    generate(generator,sk->y2,g->p,bitLengthK, 0);
    generate(generator,sk->y3,g->p,bitLengthK, 0);
    generate(generator,k1,g->p,bitLengthK, 0);
    generate(generator,k2,g->p,bitLengthK, 0);
    generate(generator,k3,g->p,bitLengthK, 0);

    //secret key
    generate(generator,sk->q1,g->p,bitLengthK, 4);//from half space
    generate(generator,sk->q2,g->p,bitLengthK, 4);//from half space
    generate(generator,sk->q3,g->p,bitLengthK, 4);//from half space

    //generate s and t such that kd=qs+t

    mpz_mul(v1,g->q,k1);
    mpz_tdiv_qr(sk->s1,sk->t1,v1,sk->q1);
    mpz_mul(v2,g->q,k2);
    mpz_tdiv_qr(sk->s2,sk->t2,v2,sk->q2);
    mpz_mul(v1,g->q,k3);
    mpz_tdiv_qr(sk->s3,sk->t3,v1,sk->q3);

    mpz_mod(sk->s1,sk->s1,g->q);
    mpz_mod(sk->s2,sk->s2,g->q);
    mpz_mod(sk->s3,sk->s3,g->q);


    //public key
    mpz_powm(pk->g1,g->gen1,sk->s1,g->p);//g1
    mpz_powm(pk->g2,g->gen1,sk->s2,g->p);//g2
    mpz_powm(pk->g3,g->gen1,sk->s3,g->p);//g3
    //c1
    mpz_powm(v1,pk->g1,sk->x1,g->p);
    mpz_powm(v2,pk->g3,sk->x3,g->p);
    mpz_mul(pk->c1,v1,v2);
    mpz_mod(pk->c1,pk->c1,g->p);
    //c2
    mpz_powm(v1,pk->g2,sk->x2,g->p);
    mpz_mul(pk->c2,v1,v2);
    mpz_mod(pk->c2,pk->c2,g->p);
    //d1
    mpz_powm(v1,pk->g1,sk->y1,g->p);
    mpz_powm(v2,pk->g3,sk->y3,g->p);
    mpz_mul(pk->d1,v1,v2);
    mpz_mod(pk->d1,pk->d1,g->p);
    //d2
    mpz_powm(v1,pk->g2,sk->y2,g->p);
    mpz_mul(pk->d2,v1,v2);
    mpz_mod(pk->d2,pk->d2,g->p);

    //h1
    mpz_add(v1,sk->t3,sk->t1);
    mpz_powm(pk->h1,g->gen1,v1,g->p);
    mpz_mod(pk->h1,pk->h1,g->p);
    //h2
    mpz_add(v1,sk->t3,sk->t2);
    mpz_powm(pk->h2,g->gen1,v1,g->p);
    mpz_mod(pk->h2,pk->h2,g->p);


    mpz_clears(v1,v2,k1,k2,k3, NULL);
}


//damgard ElGamal: sk=(x1,x2)
void keyGenerator_damgard(gmp_randstate_t generator,Cgroup_fast *glo, secretK_damgard *sk,publicK_damgard *pk,Cgroup_fast *g,unsigned int bitLengthK)
{
    //description of the group
    //glo is the group computed in main. Prime p is the same for all keygen
    mpz_set(g->p,glo->p);
    primitiveRoot_g_fast(generator,g->p,g->gen1);
    mpz_sub_ui(g->q,g->p,1);

    //secret key
    //function generate in RandomGenerator.c
    generate(generator,sk->x1,g->p,bitLengthK, 0);
    generate(generator,sk->x2,g->p,bitLengthK, 0);

    //public key
    mpz_powm(pk->pk1,g->gen1,sk->x1,g->p);
    mpz_powm(pk->pk2,g->gen1,sk->x2,g->p);

}


//FAST damgard ElGamal: sk=(x1,x2)
void keyGenerator_damgard_fast(gmp_randstate_t generator,Cgroup_fast *glo, secretK_damgard *sk,publicK *pk,Cgroup_fast *g,unsigned int bitLengthK)
{
  mpz_t v1,k,z1,z2,y;
  mpz_inits(v1,k,z1,z2,y,NULL);
  //description of the group
  mpz_set(g->p,glo->p);
  //generator
  primitiveRoot_g_fast(generator,g->p,g->gen1);
  mpz_sub_ui(g->q,g->p,1);

  //secret key
  generate(generator,k,g->p,bitLengthK, 0);//k is not in the secret key
  generate(generator,sk->x1,g->p,bitLengthK, 4);//from half space
  generate(generator,sk->x2,g->p,bitLengthK, 4);//from half space

  //generate y and z1 such that kd=yx1+z1

  mpz_mul(v1,g->q,k);
  mpz_tdiv_qr(y,z1,v1,sk->x1);

  //compute z2 such that kd=yx2+z2 so z2=kd-yx2
  mpz_mul(z2,y,sk->x2);
  mpz_sub(z2,v1,z2);
  //public key
  mpz_mod(y,y,g->q); //compute y mod d for faster expo
  //c=g^y --> b0
  mpz_powm(pk->c,g->gen1,y,g->p);
  //d=g^(z1) --> b1
  mpz_powm(pk->d,g->gen1,z1,g->p);
  //h=g^(z2) ---> b2
  mpz_powm(pk->h,g->gen1,z2,g->p);

  mpz_clears(v1,z1,k,z2,y,NULL);

}


//LINEAR damgard ElGamal: sk=(x1,x2,x3)
void keyGenerator_LD(gmp_randstate_t generator,Cgroup_fast *glo, secretK_LD *sk,publicK_LD *pk,Cgroup_fast *g,unsigned int bitLengthK)
{
    //description of the group
    //glo is the group computed in main. Prime p is the same for all keygen
    mpz_set(g->p,glo->p);
    primitiveRoot_g_fast(generator,g->p,g->gen1);
    mpz_sub_ui(g->q,g->p,1);

    //secret key
    //function generate in RandomGenerator.c
    generate(generator,sk->x1,g->p,bitLengthK, 0);
    generate(generator,sk->x2,g->p,bitLengthK, 0);
    generate(generator,sk->x3,g->p,bitLengthK, 0);

    //public key
    mpz_powm(pk->pk1,g->gen1,sk->x1,g->p);
    mpz_powm(pk->pk2,g->gen1,sk->x2,g->p);
    mpz_powm(pk->pk3,g->gen1,sk->x3,g->p);

}


//LINEAR FAST damgard ElGamal: sk=(x1,x2,x3)
void keyGenerator_LD_fast(gmp_randstate_t generator,Cgroup_fast *glo, secretK_LD *sk,publicK_LD_fast *pk,Cgroup_fast *g,unsigned int bitLengthK)
{
  mpz_t v1,k,z1,z2,z3,y;
  mpz_inits(v1,k,z1,z2,z3,y,NULL);
  //description of the group
  mpz_set(g->p,glo->p);
  //generator
  primitiveRoot_g_fast(generator,g->p,g->gen1);
  mpz_sub_ui(g->q,g->p,1);

  //secret key
  generate(generator,k,g->p,bitLengthK, 0);//k is not in the secret key
  generate(generator,sk->x1,g->p,bitLengthK, 4);//from half space
  generate(generator,sk->x2,g->p,bitLengthK, 4);//from half space
  generate(generator,sk->x3,g->p,bitLengthK, 4);//from half space

  //generate y and z1 such that kd=yx1+z1
  //v1=kd
  mpz_mul(v1,g->q,k);
  mpz_tdiv_qr(y,z1,v1,sk->x1);

  //compute z2 such that kd=yx2+z2 so z2=kd-yx2
  mpz_mul(z2,y,sk->x2);
  mpz_sub(z2,v1,z2);
  //compute z3 such that kd=yx3+z3 so z3=kd-yx3
  mpz_mul(z3,y,sk->x3);
  mpz_sub(z3,v1,z3);
  //public key
  mpz_mod(y,y,g->q); //compute y mod d for faster expo
  //b0=g^y
  mpz_powm(pk->b0,g->gen1,y,g->p);
  //b1=g^(z1)
  mpz_powm(pk->b1,g->gen1,z1,g->p);
  //b2=g^(z2)
  mpz_powm(pk->b2,g->gen1,z2,g->p);
  //b3=g^(z3)
  mpz_powm(pk->b3,g->gen1,z3,g->p);

  mpz_clears(v1,z1,k,z2,z3,y,NULL);

}
