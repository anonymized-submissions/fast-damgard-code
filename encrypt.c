#include "encrypt.h"
#include "keys.h"
#include "hashF.h"
#include "RandomGenerator.h"
#include <gmp.h>

//original, basic and variant are same
void encrypt_(gmp_randstate_t generator,CipherT *cipher, publicK pk, Cgroup gr,mpz_t msg)
{
    mpz_t k, val1, val2, alpha;
    mpz_inits(k, val1, val2, alpha, NULL);
    generate(generator,k,gr.p,0, 3);
    mpz_powm(cipher->u1,gr.g1,k,gr.p); //u1
    mpz_powm(cipher->u2,gr.g2,k,gr.p); //u2
    mpz_powm(val1,pk.h,k,gr.p);
    mpz_mul(cipher->e,val1,msg);
    mpz_mod(cipher->e, cipher->e, gr.p); //e
    hashF_(alpha, cipher->u1, cipher->u2, cipher->e);
    mpz_powm(val1,pk.c,k,gr.p);
    mpz_mul(val2,k,alpha);
    //mpz_mod(val2,val2, gr.p);
    mpz_powm(val2,pk.d,val2,gr.p);
    mpz_mul(cipher->v,val2,val1);
    mpz_mod(cipher->v,cipher->v, gr.p); //v

    mpz_clears(k, val1, val2, alpha, NULL);
}

void enc1_(mpz_t k,gmp_randstate_t generator,CipherT *cipher, publicK pk, Cgroup gr,mpz_t msg)
{
    mpz_powm(cipher->u1,gr.g1,k,gr.p); //u1
}

void enc2_(mpz_t k,gmp_randstate_t generator,CipherT *cipher, publicK pk, Cgroup gr,mpz_t msg)
{
    mpz_powm(cipher->u2,gr.g2,k,gr.p); //u2

}

void enc3_(mpz_t k,gmp_randstate_t generator,CipherT *cipher, publicK pk, Cgroup gr,mpz_t msg)
{
  mpz_t v1;
  mpz_init(v1);
  mpz_powm(v1,pk.h,k,gr.p);
  mpz_mul(cipher->e,v1,msg);
  mpz_mod(cipher->e, cipher->e, gr.p); //e
  mpz_clear(v1);
}

void enc4_(mpz_t k,gmp_randstate_t generator,CipherT *cipher, publicK pk, Cgroup gr,mpz_t msg)
{
  mpz_t v1,v2,alpha;
  mpz_inits(v1,v2,alpha,NULL);
  hashF_(alpha, cipher->u1, cipher->u2, cipher->e);
  mpz_powm(v1,pk.c,k,gr.p);
  mpz_mul(v2,k,alpha);
  //mpz_mod(val2,val2, gr.p);
  mpz_powm(v2,pk.d,v2,gr.p);
  mpz_mul(cipher->v,v2,v1);
  mpz_mod(cipher->v,cipher->v, gr.p); //v
  mpz_clears(v1,v2,alpha,NULL);
}

void encrypt_fast(gmp_randstate_t generator,CipherT_fast *cipher, publicK_fast pk, Cgroup_fast gr,mpz_t msg)
{
    mpz_t r, v1,v2, beta;
    mpz_inits(r,v1,v2,beta, NULL);
    generate(generator,r,gr.p,0,3);
    mpz_powm(cipher->u2,gr.gen1,r,gr.p); //u2=g^r
    mpz_powm(cipher->u1,pk.g1,r,gr.p); //u1=g^(sr)
    mpz_powm(v1,pk.h,r,gr.p);
    mpz_mul(cipher->e,v1,msg);
    mpz_mod(cipher->e, cipher->e, gr.p); //e=m*h^r
    hashF_(beta, cipher->u1, cipher->u2, cipher->e);//hash
    mpz_powm(v1,pk.c,r,gr.p);
    mpz_mul(v2,r,beta);
    mpz_powm(v2,pk.d,v2,gr.p);
    mpz_mul(cipher->v,v1,v2);
    mpz_mod(cipher->v,cipher->v, gr.p); //v=c^rd^(ra)
    mpz_clears(r, v1, v2, beta, NULL);
}

void enc1_fast(mpz_t r,gmp_randstate_t generator,CipherT_fast *cipher, publicK_fast pk, Cgroup_fast gr,mpz_t msg)
{

    mpz_powm(cipher->u1,pk.g1,r,gr.p); //u1=g^(sr)

}

void enc2_fast(mpz_t r,gmp_randstate_t generator,CipherT_fast *cipher, publicK_fast pk, Cgroup_fast gr,mpz_t msg)
{

    mpz_powm(cipher->u2,gr.gen1,r,gr.p); //u2=g^r

}

void enc3_fast(mpz_t r,gmp_randstate_t generator,CipherT_fast *cipher, publicK_fast pk, Cgroup_fast gr,mpz_t msg)
{
  mpz_t v1;
  mpz_init(v1);
  mpz_powm(v1,pk.h,r,gr.p);
  mpz_mul(cipher->e,v1,msg);
  mpz_mod(cipher->e, cipher->e, gr.p); //e=m*h^r
  mpz_clear(v1);
}

void enc4_fast(mpz_t r,gmp_randstate_t generator,CipherT_fast *cipher, publicK_fast pk, Cgroup_fast gr,mpz_t msg)
{
  mpz_t v1,v2,beta;
  mpz_inits(v1,v2,beta,NULL);
  hashF_(beta, cipher->u1, cipher->u2, cipher->e);//hash
  mpz_powm(v1,pk.c,r,gr.p);
  mpz_mul(v2,r,beta);
  mpz_powm(v2,pk.d,v2,gr.p);
  mpz_mul(cipher->v,v1,v2);
  mpz_mod(cipher->v,cipher->v, gr.p); //v=c^rd^(ra)
  mpz_clears(v1,v2,beta,NULL);
}

//short
void encrypt_short(gmp_randstate_t generator,CipherT_short *cipher, publicK pk, Cgroup_fast gr,mpz_t msg)
{
    mpz_t k, val1, val2, alpha,l;
    mpz_inits(k, val1, val2, alpha,l, NULL);
    generate(generator,k,gr.p,0, 3);
    mpz_powm(cipher->u,gr.gen1,k,gr.p); //u
    mpz_powm(val1,pk.h,k,gr.p);
    mpz_mul(cipher->e,val1,msg);
    mpz_mod(cipher->e, cipher->e, gr.p); //e
    hashF_(alpha, l, cipher->u, cipher->e);
    mpz_powm(val1,pk.c,k,gr.p);
    mpz_mul(val2,k,alpha);
    mpz_powm(val2,pk.d,val2,gr.p);
    mpz_mul(cipher->v,val2,val1);
    mpz_mod(cipher->v,cipher->v, gr.p); //v

    mpz_clears(k, val1, val2, alpha, l,NULL);
}

//short with fast modif
void encrypt_fast_s(gmp_randstate_t generator,CipherT_short *cipher, publicK_fast pk, Cgroup_fast gr,mpz_t msg)
{
    mpz_t k, val1, val2, alpha,l;
    mpz_inits(k, val1, val2, alpha,l, NULL);
    generate(generator,k,gr.p,0, 3);
    mpz_powm(cipher->u,pk.g1,k,gr.p); //u
    mpz_powm(val1,pk.h,k,gr.p);
    mpz_mul(cipher->e,val1,msg);
    mpz_mod(cipher->e, cipher->e, gr.p); //e
    hashF_(alpha, l, cipher->u, cipher->e);
    mpz_powm(val1,pk.c,k,gr.p);
    mpz_mul(val2,k,alpha);
    //mpz_mod(val2,val2,gr.q);
    mpz_powm(val2,pk.d,val2,gr.p);
    mpz_mul(cipher->v,val2,val1);
    mpz_mod(cipher->v,cipher->v, gr.p); //v

    mpz_clears(k, val1, val2, alpha, l,NULL);
}


//LCS
void encrypt_LCS(gmp_randstate_t generator,CipherT_LCS *cipher, publicK_LCS pk, Cgroup_LCS gr,mpz_t msg)
{
    mpz_t r1,r2, val1, val2, val3, alpha;
    mpz_inits(r1,r2, val1, val2,val3, alpha, NULL);
    generate(generator,r1,gr.p,0, 3);
    generate(generator,r2,gr.p,0, 3);
    mpz_powm(cipher->u1,gr.g1,r1,gr.p); //u1
    mpz_powm(cipher->u2,gr.g2,r2,gr.p); //u2
    //u3
    mpz_add(val1,r1,r2);
    mpz_mod(val1, val1, gr.q);
    mpz_powm(cipher->u3,gr.g3,val1,gr.p);

    mpz_powm(val1,pk.h1,r1,gr.p);
    mpz_powm(val2,pk.h2,r2,gr.p);
    mpz_mul(val1,val1,val2);
    mpz_mul(cipher->e,val1,msg);
    mpz_mod(cipher->e, cipher->e, gr.p); //e

    //hash
    hashF4_(alpha, cipher->u1, cipher->u2, cipher->u3, cipher->e);

    //v
    mpz_powm(val1,pk.c1,r1,gr.p);
    mpz_mul(val2,r1,alpha);
    mpz_mod(val2,val2, gr.q);
    mpz_powm(val2,pk.d1,val2,gr.p);
    mpz_mul(val3,val2,val1);

    mpz_powm(val1,pk.c2,r2,gr.p);
    mpz_mul(val2,r2,alpha);
    mpz_mod(val2,val2, gr.q);
    mpz_powm(val2,pk.d2,val2,gr.p);
    mpz_mul(val1,val2,val1);

    mpz_mul(cipher->v,val1,val3);
    mpz_mod(cipher->v,cipher->v,gr.p);

    mpz_clears(r1,r2, val1, val2,val3, alpha, NULL);
}

//Fast LCS
void encrypt_FLCS(gmp_randstate_t generator,CipherT_LCS *cipher, publicK_FLCS pk, Cgroup_fast gr,mpz_t msg)
{
    mpz_t r1,r2, val1, val2, val3, alpha;
    mpz_inits(r1,r2, val1, val2,val3, alpha, NULL);
    generate(generator,r1,gr.p,0, 3);
    generate(generator,r2,gr.p,0, 3);
    mpz_powm(cipher->u1,pk.g1,r1,gr.p); //u1
    mpz_powm(cipher->u2,pk.g2,r2,gr.p); //u2
    //u3
    mpz_add(val1,r1,r2);
    mpz_mod(val1, val1, gr.q);
    mpz_powm(cipher->u3,pk.g3,val1,gr.p);

    mpz_powm(val1,pk.h1,r1,gr.p);
    mpz_powm(val2,pk.h2,r2,gr.p);
    mpz_mul(val1,val1,val2);
    mpz_mul(cipher->e,val1,msg);
    mpz_mod(cipher->e, cipher->e, gr.p); //e

    //hash
    hashF4_(alpha, cipher->u1, cipher->u2, cipher->u3, cipher->e);

    //v
    mpz_mul(val1,pk.c1,pk.g3);
    mpz_mod(val1,val1,gr.p);
    mpz_powm(val1,val1,r1,gr.p);
    mpz_mul(val2,r1,alpha);
    mpz_mod(val2,val2,gr.q);
    mpz_powm(val2,pk.d1,val2,gr.p);
    mpz_mul(val3,val2,val1);

    mpz_mul(val1,pk.c2,pk.g3);
    mpz_mod(val1,val1,gr.p);
    mpz_powm(val1,val1,r2,gr.p);
    mpz_mul(val2,r2,alpha);
    mpz_mod(val2,val2,gr.q);
    mpz_powm(val2,pk.d2,val2,gr.p);
    mpz_mul(val1,val2,val1);

    mpz_mul(cipher->v,val1,val3);
    mpz_mod(cipher->v,cipher->v,gr.p);

    mpz_clears(r1,r2, val1, val2,val3, alpha, NULL);
}


//Fast LCS variant: v=(c1+d1^a)^r1 * (c2+d2^a)^r2
void encrypt_FLCS_var(gmp_randstate_t generator,CipherT_LCS *cipher, publicK_FLCS pk, Cgroup_fast gr,mpz_t msg)
{
    mpz_t r1,r2, val1, val2, val3, alpha;
    mpz_inits(r1,r2, val1, val2,val3, alpha, NULL);
    generate(generator,r1,gr.p,0, 3);
    generate(generator,r2,gr.p,0, 3);
    mpz_powm(cipher->u1,pk.g1,r1,gr.p); //u1
    mpz_powm(cipher->u2,pk.g2,r2,gr.p); //u2
    //u3
    mpz_add(val1,r1,r2);
    mpz_mod(val1, val1, gr.q);
    mpz_powm(cipher->u3,pk.g3,val1,gr.p);

    mpz_powm(val1,pk.h1,r1,gr.p);
    mpz_powm(val2,pk.h2,r2,gr.p);
    mpz_mul(val1,val1,val2);
    mpz_mul(cipher->e,val1,msg);
    mpz_mod(cipher->e, cipher->e, gr.p); //e

    //hash
    hashF4_(alpha, cipher->u1, cipher->u2, cipher->u3, cipher->e);

    //v
    mpz_powm(val1,pk.c1,r1,gr.p);
    mpz_mul(val2,r1,alpha);
    mpz_mod(val2,val2,gr.q);
    mpz_powm(val2,pk.d1,val2,gr.p);
    mpz_mul(val3,val2,val1);

    mpz_powm(val1,pk.c2,r2,gr.p);
    mpz_mul(val2,r2,alpha);
    mpz_mod(val2,val2,gr.q);
    mpz_powm(val2,pk.d2,val2,gr.p);
    mpz_mul(val1,val2,val1);

    mpz_mul(cipher->v,val1,val3);
    mpz_mod(cipher->v,cipher->v,gr.p);

    mpz_clears(r1,r2, val1, val2,val3, alpha, NULL);
}

//SHORT LCS
void encrypt_LCS_short(gmp_randstate_t generator,CipherT_LCS *cipher, publicK_LCS pk, Cgroup_LCS gr,mpz_t msg)
{
    mpz_t r1,r2, val1, val2, val3, alpha;
    mpz_inits(r1,r2, val1, val2,val3, alpha, NULL);
    generate(generator,r1,gr.p,0, 3);
    generate(generator,r2,gr.p,0, 3);
    mpz_powm(cipher->u1,gr.g1,r1,gr.p); //u1
    mpz_powm(cipher->u2,gr.g2,r2,gr.p); //u2
    //u3
    mpz_add(val1,r1,r2);
    //mpz_mod(val1, val1, gr.q);
    mpz_powm(cipher->u3,gr.g3,val1,gr.p);

    mpz_powm(val1,pk.h1,r1,gr.p);
    mpz_powm(val2,pk.h2,r2,gr.p);
    mpz_mul(val1,val1,val2);
    mpz_mul(cipher->e,val1,msg);
    mpz_mod(cipher->e, cipher->e, gr.p); //e

    //hash
    hashF4_(alpha, cipher->u1, cipher->u2, cipher->u3, cipher->e);

    //v
    mpz_mul(val1,pk.c1,gr.g3);
    mpz_mod(val1,val1,gr.p);
    mpz_powm(val1,val1,r1,gr.p);
    mpz_mul(val2,r1,alpha);
    mpz_mod(val2,val2,gr.q);
    mpz_powm(val2,pk.d1,val2,gr.p);
    mpz_mul(val3,val2,val1);

    mpz_mul(val1,pk.c2,gr.g3);
    mpz_mod(val1,val1,gr.p);
    mpz_powm(val1,val1,r2,gr.p);
    mpz_mul(val2,r2,alpha);
    mpz_mod(val2,val2,gr.q);
    mpz_powm(val2,pk.d2,val2,gr.p);
    mpz_mul(val1,val2,val1);

    mpz_mul(cipher->v,val1,val3);
    mpz_mod(cipher->v,cipher->v,gr.p);

    mpz_clears(r1,r2, val1, val2,val3, alpha, NULL);
}

//Fast LCS pascal version: v=(c1+d1^a)^r1 * (c2+d2^a)^r2
void encrypt_FLCS_v1(gmp_randstate_t generator,CipherT_LCS *cipher, publicK_FLCS pk, Cgroup_fast gr,mpz_t msg)
{
    mpz_t r1,r2, val1, val2, val3, alpha;
    mpz_inits(r1,r2, val1, val2,val3, alpha, NULL);
    generate(generator,r1,gr.p,0, 3);
    generate(generator,r2,gr.p,0, 3);
    mpz_powm(cipher->u1,pk.g1,r1,gr.p); //u1
    mpz_powm(cipher->u2,pk.g2,r2,gr.p); //u2
    //u3
    mpz_add(val1,r1,r2);
    mpz_mod(val1, val1, gr.q);
    mpz_powm(cipher->u3,pk.g3,val1,gr.p);

    mpz_powm(val1,pk.h1,r1,gr.p);
    mpz_powm(val2,pk.h2,r2,gr.p);
    mpz_mul(val1,val1,val2);
    mpz_mul(cipher->e,val1,msg);
    mpz_mod(cipher->e, cipher->e, gr.p); //e

    //hash
    hashF4_(alpha, cipher->u1, cipher->u2, cipher->u3, cipher->e);

    //v
    mpz_powm(val1,pk.c1,r1,gr.p);
    mpz_mul(val2,r1,alpha);
    mpz_mod(val2,val2,gr.q);
    mpz_powm(val2,pk.d1,val2,gr.p);
    mpz_mul(val3,val2,val1);

    mpz_powm(val1,pk.c2,r2,gr.p);
    mpz_mul(val2,r2,alpha);
    mpz_mod(val2,val2,gr.q);
    mpz_powm(val2,pk.d2,val2,gr.p);
    mpz_mul(val1,val2,val1);

    mpz_mul(cipher->v,val1,val3);
    mpz_mod(cipher->v,cipher->v,gr.p);

    mpz_clears(r1,r2, val1, val2,val3, alpha, NULL);
}


//damgard elgamal
void encrypt_damgard(gmp_randstate_t generator,CipherT_short *cipher, publicK_damgard pk, Cgroup_fast gr,mpz_t msg)
{
    mpz_t k;
    mpz_init(k);
    generate(generator,k,gr.p,0, 3); //random
    mpz_powm(cipher->u,gr.gen1,k,gr.p); //u=g^k -->c0
    mpz_powm(cipher->e,pk.pk1,k,gr.p); //e=(pk1)^k -->c1

    mpz_powm(cipher->v,pk.pk2,k,gr.p); //v=(pk2)^k.m -->c2
    mpz_mul(cipher->v,cipher->v,msg);
    mpz_mod(cipher->v,cipher->v,gr.p);
    mpz_clear(k);
}


// fast damgard elgamal
void encrypt_damgard_fast(gmp_randstate_t generator,CipherT_short *cipher, publicK pk, Cgroup_fast gr,mpz_t msg)
{
    mpz_t k;
    mpz_init(k);
    generate(generator,k,gr.p,0, 3); //random
    mpz_powm(cipher->u,pk.c,k,gr.p); //u=b0^k -->c0
    mpz_powm(cipher->e,pk.d,k,gr.p); //e=(b1)^k -->c1

    mpz_powm(cipher->v,pk.h,k,gr.p); //v=(b2)^k -->c2
    mpz_mul(cipher->v,cipher->v,msg);
    mpz_mod(cipher->v,cipher->v,gr.p);

    mpz_clear(k);
}

//LINEAR damgard elgamal ------------------------------------
void encrypt_LD(gmp_randstate_t generator,CipherT_LD *cipher, publicK_LD pk, Cgroup_fast gr,mpz_t msg)
{
    mpz_t r1,r2;
    mpz_inits(r1,r2,NULL);
    generate(generator,r1,gr.p,0, 3); //random
    generate(generator,r2,gr.p,0, 3); //random
    mpz_powm(cipher->u1,gr.gen1,r1,gr.p); //u1=g^r1
    mpz_powm(cipher->u2,gr.gen1,r2,gr.p); //u2=g^r2
    mpz_powm(cipher->c1,pk.pk1,r1,gr.p); //c1=(pk1)^r1
    mpz_powm(cipher->c2,pk.pk2,r2,gr.p); //c2=(pk2)^r2

    //c3=M.(pk3)^(r1+r2)
    mpz_add(r1,r1,r2);
    mpz_powm(cipher->c3,pk.pk3,r1,gr.p);
    mpz_mul(cipher->c3,cipher->c3,msg);
    mpz_mod(cipher->c3,cipher->c3,gr.p);
    mpz_clears(r1,r2,NULL);
}

//LINEAR FAST damgard elgamal ------------------------------------
void encrypt_LD_fast(gmp_randstate_t generator,CipherT_LD *cipher, publicK_LD_fast pk, Cgroup_fast gr,mpz_t msg)
{
    mpz_t r1,r2;
    mpz_inits(r1,r2,NULL);
    generate(generator,r1,gr.p,0, 3); //random
    generate(generator,r2,gr.p,0, 3); //random
    mpz_powm(cipher->u1,pk.b0,r1,gr.p); //u1=b0^r1
    mpz_powm(cipher->u2,pk.b0,r2,gr.p); //u2=b0^r2
    mpz_powm(cipher->c1,pk.b1,r1,gr.p); //c1=(b1)^r1
    mpz_powm(cipher->c2,pk.b2,r2,gr.p); //c2=(b2)^r2

    //c3=M.(b3)^(r1+r2)
    mpz_add(r1,r1,r2);
    mpz_powm(cipher->c3,pk.b3,r1,gr.p);
    mpz_mul(cipher->c3,cipher->c3,msg);
    mpz_mod(cipher->c3,cipher->c3,gr.p);
    mpz_clears(r1,r2,NULL);
}
