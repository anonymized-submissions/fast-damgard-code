#include "decrypt.h"
#include "keys.h"
#include "hashF.h"
#include <gmp.h>

//original+basic: only one verif SAME as basic
void verif_(secretK sk, Cgroup gr, CipherT cipherT)
{
    mpz_t alpha, val1, val2, val3;
    mpz_inits(alpha, val1, val2,val3, NULL);
    hashF_(alpha, cipherT.u1, cipherT.u2, cipherT.e);
    mpz_powm(val1,cipherT.u1,sk.x1,gr.p);
    mpz_powm(val2,cipherT.u2,sk.x2,gr.p);
    mpz_mul(val1, val1, val2);
    mpz_mod(val1, val1, gr.p);//modular multiplication not implemented so first multiply then modulus

    mpz_powm(val3,cipherT.u1,sk.y1,gr.p);
    mpz_powm(val2,cipherT.u2,sk.y2,gr.p);
    mpz_mul(val2, val3, val2);
    mpz_mod(val2, val2, gr.p);
    mpz_powm(val3,val2,alpha,gr.p);

    mpz_mul(val1, val3, val1);
    mpz_mod(val1, val1, gr.p);
    //compare val1 with v; return 0 if equal
    mpz_cmp(val1,cipherT.v);

    mpz_clears(alpha, val1, val2,val3, NULL);
}
//original
void decrypt_(mpz_t plainT, secretK sk, Cgroup gr, CipherT cipherT)
{
    mpz_t alpha, val1, val2, val3;
    mpz_inits(alpha, val1, val2,val3, NULL);

    mpz_powm(val3,cipherT.u1,sk.z1,gr.p);
    mpz_powm(val2,cipherT.u2,sk.z2,gr.p);

    mpz_mul(val2, val3, val2);
    mpz_mod(val2, val2, gr.p);
    mpz_invert(val3, val2,gr.p);
    mpz_mul(plainT,cipherT.e,val3);
    mpz_mod(plainT, plainT, gr.p);
    mpz_clears(alpha, val1, val2,val3, NULL);
}

//basic: e/u1^z
void decrypt_basic(mpz_t plainT, secretK sk, Cgroup gr, CipherT cipherT)
{
    mpz_t alpha, val1, val2, val3;
    mpz_inits(alpha, val1, val2,val3, NULL);

    mpz_powm(val3,cipherT.u1,sk.z1,gr.p);
    mpz_mod(val3, val3, gr.p);
    mpz_invert(val3, val3,gr.p);
    mpz_mul(plainT,cipherT.e,val3);
    mpz_mod(plainT, plainT, gr.p);

    mpz_clears(alpha, val1, val2,val3, NULL);
}

//variant 1st verif : v=u1^(x+ya)
void verif1_variant(secretK_variant sk, Cgroup gr, CipherT cipherT)
{
    mpz_t alpha, val1;
    mpz_inits(alpha, val1, NULL);
    hashF_(alpha, cipherT.u1, cipherT.u2, cipherT.e);
    mpz_mul(val1, sk.y, alpha);
    mpz_add(val1,val1,sk.x);
    mpz_powm(val1,cipherT.u1,val1,gr.p);
    mpz_cmp(val1,cipherT.v);
    mpz_clears(alpha, val1,NULL);
}

//variant 2nd verif : u1^w=u2
void verif2_variant(secretK_variant sk, Cgroup gr, CipherT cipherT)
{
    mpz_t val2;
    mpz_inits(val2);
    mpz_powm(val2,cipherT.u1,sk.w,gr.p);
    mpz_cmp(val2,cipherT.u2);
    mpz_clear(val2);
}

//variant dec : e/u1^z
void decrypt_variant(mpz_t plainT, secretK_variant sk, Cgroup gr, CipherT cipherT)
{
    mpz_t val1;
    mpz_init(val1);
    mpz_powm(val1,cipherT.u1,sk.z,gr.p);
    mpz_invert(val1, val1,gr.p);
    mpz_mul(plainT,cipherT.e,val1);
    mpz_mod(plainT, plainT, gr.p);
    mpz_clear(val1);

}
//fast 1st verif : v=u1^(x+ya)
void verif1_fast(secretK_fast sk, Cgroup_fast gr, CipherT_fast cipherT)
{
  mpz_t alpha, val1;
  mpz_inits(alpha, val1, NULL);
  hashF_(alpha, cipherT.u1, cipherT.u2, cipherT.e);
  mpz_mul(val1, sk.y, alpha);
  mpz_add(val1,val1,sk.x);
  mpz_mod(val1,val1,gr.q);
  mpz_powm(val1,cipherT.u1,val1,gr.p);
  mpz_cmp(val1,cipherT.v);
  mpz_clears(alpha, val1, NULL);
}

//fast 2nd verif : u2^s=u1
void verif2_fast(secretK_fast sk, Cgroup_fast gr, CipherT_fast cipherT)
{
  mpz_t val2;
  mpz_init(val2);
  mpz_powm(val2,cipherT.u2,sk.s,gr.p);
  mpz_cmp(val2,cipherT.u1);
  mpz_clear(val2);

}
//fast 2nd verif : u1^q u2^t=1
void verif3_fast(secretK_fast sk, Cgroup_fast gr, CipherT_fast cipherT)
{
  mpz_t v1,v2;
  mpz_inits(v1,v2,NULL);
  mpz_powm(v1,cipherT.u1,sk.quo,gr.p);
  mpz_powm(v2,cipherT.u2,sk.t,gr.p);
  mpz_mul(v1,v1,v2);
  mpz_mod(v1,v1,gr.p);
  mpz_cmp_ui(v1,1);
  mpz_clears(v1,v2,NULL);

}
//keep in memory of u_1^q (which is used in decrypt)
void verif3_opti_fast(mpz_t u1q,secretK_fast sk, Cgroup_fast gr, CipherT_fast cipherT)
{
  mpz_t v2;
  mpz_init(v2);
  mpz_powm(u1q,cipherT.u1,sk.quo,gr.p);
  mpz_powm(v2,cipherT.u2,sk.t,gr.p);
  mpz_mul(v2,v2,u1q);
  mpz_mod(v2,v2,gr.p);
  mpz_cmp_ui(v2,1);
  mpz_clear(v2);

}

//fast 2nd verif : u1^(q-t)*(u1u2)^t
void verif4_fast(secretK_fast sk, Cgroup_fast gr, CipherT_fast cipherT)
{
  mpz_t v1,v2;
  mpz_inits(v1,v2,NULL);
  mpz_sub(v1,sk.quo,sk.t);
  mpz_powm(v1,cipherT.u1,v1,gr.p);
  mpz_mul(v2,cipherT.u1,cipherT.u2);
  mpz_mod(v2,v2,gr.p);
  mpz_powm(v2,v2,sk.t,gr.p);
  mpz_mul(v1,v1,v2);
  mpz_mod(v1,v1,gr.p);

  mpz_clears(v1,v2,NULL);

}
// e*u_1^q=m
void decrypt_fast(mpz_t plainT, secretK_fast sk, Cgroup_fast gr, CipherT_fast cipherT)
{
  mpz_t val1;
  mpz_init(val1);
  mpz_powm(val1,cipherT.u1,sk.quo,gr.p);
  mpz_mul(plainT,cipherT.e,val1);
  mpz_mod(plainT, plainT, gr.p);
  mpz_clear(val1);
}

// e*u_1^q=m with u1^q already in memory
void decrypt_opti(mpz_t u1q, mpz_t plainT, secretK_fast sk, Cgroup_fast gr, CipherT_fast cipherT)
{
  mpz_mul(plainT,cipherT.e,u1q);
  mpz_mod(plainT, plainT, gr.p);
}


//short
void decrypt_short(mpz_t plainT, secretK_short sk, Cgroup_fast gr, CipherT_short cipherT)
{
    mpz_t val1;
    mpz_inits(val1, NULL);

    //e/u^s
    mpz_powm(val1,cipherT.u,sk.s,gr.p);
    mpz_invert(val1,val1,gr.p);
    mpz_mul(plainT,cipherT.e,val1);
    mpz_mod(plainT,plainT,gr.p);

    mpz_clears(val1, NULL);
}

//short
void verif_short(mpz_t plainT, secretK_short sk, Cgroup_fast gr, CipherT_short cipherT)
{
    mpz_t alpha, val1, val2,val4;
    mpz_inits(alpha, val1, val2,val4, NULL);

    hashF_(alpha, val1, cipherT.u, cipherT.e);
    mpz_mul(val1,alpha,sk.ap);
    mpz_add(val1,val1,sk.a);
    mpz_mod(val1,val1,gr.q);//a+alpha*ap
    mpz_powm(val1,cipherT.u,val1,gr.p);

    mpz_mul(val2,alpha,sk.bp);
    mpz_add(val2,val2,sk.b);
    mpz_mod(val2,val2,gr.q);//b+alpha*bp
    mpz_invert(val4,plainT,gr.p);
    mpz_mul(val4,cipherT.e,val4);
    mpz_mod(val4,val4,gr.p);
    mpz_powm(val4,val4,val2,gr.p);

    mpz_mul(val1,val1,val4);
    mpz_mod(val1,val1,gr.p);
    mpz_cmp(val1,cipherT.v);

    mpz_clears(alpha, val1, val2,val4, NULL);
}


//short with fast modif
void decrypt_fast_s(mpz_t plainT, secretK_short sk, Cgroup_fast gr, CipherT_short cipherT)
{
    mpz_t val1;
    mpz_inits(val1, NULL);

    //e/u^s
    mpz_powm(val1,cipherT.u,sk.s,gr.p);
    mpz_mul(plainT,cipherT.e,val1);
    mpz_mod(plainT,plainT,gr.p);

    mpz_clears(val1, NULL);
}

//short with fast modif
void verif_fast_s(mpz_t plainT, secretK_short sk, Cgroup_fast gr, CipherT_short cipherT)
{
    mpz_t alpha, val1, val2,val4;
    mpz_inits(alpha, val1, val2,val4, NULL);

    hashF_(alpha, val1, cipherT.u, cipherT.e);
    mpz_mul(val1,alpha,sk.ap);
    mpz_add(val1,val1,sk.a);
    mpz_mod(val1,val1,gr.q);//a+alpha*ap
    mpz_powm(val1,cipherT.u,val1,gr.p);

    mpz_mul(val2,alpha,sk.bp);
    mpz_add(val2,val2,sk.b);
    mpz_mod(val2,val2,gr.q);//b+alpha*bp
    mpz_invert(val4,plainT,gr.p);
    mpz_mul(val4,cipherT.e,val4);
    mpz_mod(val4,val4,gr.p);
    //gmp_printf("e/m : %Zu",val4);
    mpz_powm(val4,val4,val2,gr.p);

    mpz_mul(val1,val1,val4);
    mpz_mod(val1,val1,gr.p);
    mpz_cmp(val1,cipherT.v);


    mpz_clears(alpha, val1, val2,val4, NULL);
}

//LCS verif
void verif_LCS(secretK_LCS sk, Cgroup_LCS gr, CipherT_LCS cipherT)
{
    mpz_t alpha, val1, val2, val3;
    mpz_inits(alpha, val1, val2,val3, NULL);
    hashF4_(alpha, cipherT.u1, cipherT.u2, cipherT.u3, cipherT.e);

    //u1^(x1+ay1)
    mpz_mul(val1,alpha,sk.y1);
    mpz_add(val1,val1,sk.x1);
    mpz_mod(val1,val1,gr.q);
    mpz_powm(val1,cipherT.u1,val1,gr.p);
    //u2^(x2+ay2)
    mpz_mul(val2,alpha,sk.y2);
    mpz_add(val2,val2,sk.x2);
    mpz_mod(val2,val2,gr.q);
    mpz_powm(val2,cipherT.u2,val2,gr.p);
    //u3^(x3+ay3)
    mpz_mul(val3,alpha,sk.y3);
    mpz_add(val3,val3,sk.x3);
    mpz_mod(val3,val3,gr.q);
    mpz_powm(val3,cipherT.u3,val3,gr.p);

    mpz_mul(val1,val1,val2);
    mpz_mul(val1,val1,val3);
    mpz_mod(val1,val1,gr.p);
    //compare val1 with v; return 0 if equal
    mpz_cmp(val1,cipherT.v);

    mpz_clears(alpha, val1, val2,val3, NULL);
}
//LCS
void decrypt_LCS(mpz_t plainT, secretK_LCS sk, Cgroup_LCS gr, CipherT_LCS cipherT)
{
    mpz_t alpha, val1, val2, val3;
    mpz_inits(alpha, val1, val2,val3, NULL);

    mpz_powm(val1,cipherT.u1,sk.z1,gr.p);
    mpz_powm(val2,cipherT.u2,sk.z2,gr.p);
    mpz_powm(val3,cipherT.u3,sk.z3,gr.p);

    mpz_mul(val1,val1,val2);
    mpz_mul(val1,val1,val3);
    mpz_mod(val1,val1,gr.p);

    mpz_invert(val1, val1,gr.p);
    mpz_mul(plainT,cipherT.e,val1);
    mpz_mod(plainT, plainT, gr.p);
    mpz_clears(alpha, val1, val2,val3, NULL);
}


//Fast LCS verif
void verif_FLCS(secretK_FLCS sk, Cgroup_fast gr, CipherT_LCS cipherT)
{
    mpz_t alpha, val1, val2;
    mpz_inits(alpha, val1, val2, NULL);
    hashF4_(alpha, cipherT.u1, cipherT.u2, cipherT.u3, cipherT.e);

    //u1^(x1+ay1)
    mpz_mul(val1,alpha,sk.y1);
    mpz_add(val1,val1,sk.x1);
    mpz_mod(val1,val1,gr.q);
    mpz_powm(val1,cipherT.u1,val1,gr.p);
    //u2^(x2+ay2)
    mpz_mul(val2,alpha,sk.y2);
    mpz_add(val2,val2,sk.x2);
    mpz_mod(val2,val2,gr.q);
    mpz_powm(val2,cipherT.u2,val2,gr.p);

    mpz_mul(val1,val1,val2);
    mpz_mul(val1,val1,cipherT.u3);
    mpz_mod(val1,val1,gr.p);
    //compare val1 with v; return 0 if equal
    mpz_cmp(val1,cipherT.v);

    mpz_clears(alpha, val1, val2, NULL);
}
//Fast LCS
void decrypt_FLCS(mpz_t plainT, secretK_FLCS sk, Cgroup_fast gr, CipherT_LCS cipherT)
{
    mpz_t alpha, val1, val2;
    mpz_inits(alpha, val1, val2, NULL);

    mpz_powm(val1,cipherT.u1,sk.q1,gr.p);
    mpz_powm(val2,cipherT.u2,sk.q2,gr.p);

    mpz_mul(val1,val1,val2);
    mpz_mul(plainT,val1,cipherT.e);
    mpz_mod(plainT,plainT,gr.p);

    mpz_clears(alpha, val1, val2, NULL);
}

////////////////// VARIANT : u1^(x1+ay1)*u2^(x2+ay2)=v and (u1^q1*u1^t1)(u2^q2*u2^t2)=u3
//u1^q1 * u2^q2 is stored for dec phase
//Fast LCS verif variant
void verif_FLCS_variant(mpz_t tmp_dec,secretK_FLCS sk, Cgroup_fast gr, CipherT_LCS cipherT)
{
    mpz_t alpha, val1, val2;
    mpz_inits(alpha, val1, val2, NULL);
    hashF4_(alpha, cipherT.u1, cipherT.u2, cipherT.u3, cipherT.e);

    //u1^(x1+ay1)
    mpz_mul(val1,alpha,sk.y1);
    mpz_add(val1,val1,sk.x1);
    mpz_mod(val1,val1,gr.q);
    mpz_powm(val1,cipherT.u1,val1,gr.p);
    //u2^(x2+ay2)
    mpz_mul(val2,alpha,sk.y2);
    mpz_add(val2,val2,sk.x2);
    mpz_mod(val2,val2,gr.q);
    mpz_powm(val2,cipherT.u2,val2,gr.p);

    mpz_mul(val1,val1,val2);
    mpz_mod(val1,val1,gr.p);
    //compare val1 with v; return 0 if equal
    mpz_cmp(val1,cipherT.v);

    //second verif
    mpz_powm(val1,cipherT.u1,sk.q1,gr.p);
    mpz_powm(val2,cipherT.u2,sk.q2,gr.p);
    mpz_mul(tmp_dec,val1,val2);
    mpz_mod(tmp_dec,tmp_dec,gr.p);

    mpz_powm(val1,cipherT.u1,sk.t1,gr.p);
    mpz_powm(val2,cipherT.u2,sk.t2,gr.p);
    mpz_mul(val1,val1,val2);
    mpz_mul(val1,val1,tmp_dec);
    mpz_mod(val1,val1,gr.p);
    mpz_cmp(val1,cipherT.u3);
    mpz_clears(alpha, val1, val2, NULL);
}
//Fast LCS variant
void decrypt_FLCS_var(mpz_t tmp_dec,mpz_t plainT, secretK_FLCS sk, Cgroup_fast gr, CipherT_LCS cipherT)
{
    mpz_t alpha, val1, val2;
    mpz_inits(alpha, val1, val2, NULL);

    mpz_mul(plainT,tmp_dec,cipherT.e);
    mpz_mod(plainT,plainT,gr.p);

    mpz_clears(alpha, val1, val2, NULL);
}

//short LCS
void decrypt_LCS_short(mpz_t plainT, secretK_LCS_short sk, Cgroup_LCS gr, CipherT_LCS cipherT)
{
    mpz_t val1,val2;
    mpz_inits(val1,val2, NULL);

    //e/(u1^s1*u2^s2)
    mpz_powm(val1,cipherT.u1,sk.s1,gr.p);
    mpz_powm(val2,cipherT.u2,sk.s2,gr.p);
    mpz_mul(val1,val1,val2);
    mpz_mod(val1,val1,gr.p);
    mpz_invert(val1,val1,gr.p);
    mpz_mul(plainT,cipherT.e,val1);
    mpz_mod(plainT,plainT,gr.p);

    mpz_clears(val1,val2, NULL);
}

//short LCS
void verif_LCS_short(mpz_t plainT, secretK_LCS_short sk, Cgroup_LCS gr, CipherT_LCS cipherT)
{
    mpz_t alpha, val1, val2,val3,val4;
    mpz_inits(alpha, val1, val2,val3,val4, NULL);
    //eM^(-1)
    mpz_invert(val4,plainT,gr.p);
    mpz_mul(val4,cipherT.e,val4);
    mpz_mod(val4,val4,gr.p);

    hashF4_(alpha, cipherT.u1, cipherT.u2, cipherT.u3, cipherT.e);
    //u1
    mpz_mul(val1,alpha,sk.ap1);
    mpz_add(val1,val1,sk.a1);
    mpz_mod(val1,val1,gr.q);//a1+alpha*a1p
    mpz_powm(val1,cipherT.u1,val1,gr.p);

    mpz_mul(val2,alpha,sk.bp1);
    mpz_add(val2,val2,sk.b1);
    mpz_mod(val2,val2,gr.q);//b1+alpha*b1p
    mpz_powm(val2,val4,val2,gr.p);

    mpz_mul(val3,val1,val2);
    //mpz_mod(val3,val3,gr.p);
    //u2
    mpz_mul(val1,alpha,sk.ap2);
    mpz_add(val1,val1,sk.a2);
    mpz_mod(val1,val1,gr.q);//a2+alpha*a2p
    mpz_powm(val1,cipherT.u2,val1,gr.p);

    mpz_mul(val2,alpha,sk.bp2);
    mpz_add(val2,val2,sk.b2);
    mpz_mod(val2,val2,gr.q);//b+alpha*bp
    mpz_powm(val2,val4,val2,gr.p);

    mpz_mul(val1,val1,val2);
    mpz_mul(val3,val1,val3);
    mpz_mul(val3,val3,cipherT.u3);
    mpz_mod(val3,val3,gr.p);

    mpz_cmp(val3,cipherT.v);

    mpz_clears(alpha, val1, val2,val3,val4, NULL);
}

//Fast LCS verif pascal
void verif_FLCS_v1(secretK_FLCS_3 sk, Cgroup_fast gr, CipherT_LCS cipherT)
{
    mpz_t alpha, val1, val2;
    mpz_inits(alpha, val1, val2, NULL);
    hashF4_(alpha, cipherT.u1, cipherT.u2, cipherT.u3, cipherT.e);

    //u1^(x1+ay1)
    mpz_mul(val1,alpha,sk.y1);
    mpz_add(val1,val1,sk.x1);
    mpz_mod(val1,val1,gr.q);
    mpz_powm(val1,cipherT.u1,val1,gr.p);
    //u2^(x2+ay2)
    mpz_mul(val2,alpha,sk.y2);
    mpz_add(val2,val2,sk.x2);
    mpz_mod(val2,val2,gr.q);
    mpz_powm(val2,cipherT.u2,val2,gr.p);

    mpz_mul(val1,val1,val2);

    //u3^(x3+ay3)
    mpz_mul(val2,alpha,sk.y3);
    mpz_add(val2,val2,sk.x3);
    mpz_mod(val2,val2,gr.q);
    mpz_powm(val2,cipherT.u3,val2,gr.p);

    mpz_mul(val1,val1,val2);
    mpz_mod(val1,val1,gr.p);
    //compare val1 with v; return 0 if equal
    mpz_cmp(val1,cipherT.v);


    mpz_clears(alpha, val1, val2, NULL);
}
//Fast LCS pascal
void decrypt_FLCS_v1(mpz_t plainT, secretK_FLCS_3 sk, Cgroup_fast gr, CipherT_LCS cipherT)
{
    mpz_t alpha, val1, val2;
    mpz_inits(alpha, val1, val2, NULL);

    mpz_powm(val1,cipherT.u1,sk.q1,gr.p);
    mpz_powm(val2,cipherT.u2,sk.q2,gr.p);
    mpz_mul(val1,val1,val2);

    mpz_powm(val2,cipherT.u3,sk.q3,gr.p);
    mpz_mul(val1,val1,val2);

    mpz_mul(plainT,val1,cipherT.e);
    mpz_mod(plainT,plainT,gr.p);

    mpz_clears(alpha, val1, val2, NULL);
}

//////////////////////////////////////////////////////////
////////////////// DAMGARD ELGAMAL ///////////////////////
//////////////////////////////////////////////////////////


//********* Original *****************

//verif damgard : c0^(sk1)=c1
void verif_damgard(secretK_damgard sk, Cgroup_fast gr, CipherT_short cipherT)
{
    mpz_t val2;
    mpz_init(val2);
    mpz_powm(val2,cipherT.u,sk.x1,gr.p);
    mpz_cmp(val2,cipherT.e);
    mpz_clear(val2);
}

//dec damgard: c2/0e^(sk2) --> v/e^(sk2)
void decrypt_damgard(mpz_t plainT, secretK_damgard sk, Cgroup_fast gr, CipherT_short cipherT)
{
    mpz_t val1;
    mpz_inits(val1, NULL);

    mpz_powm(val1,cipherT.u,sk.x2,gr.p);
    mpz_invert(val1, val1,gr.p);
    mpz_mul(plainT,cipherT.v,val1);
    mpz_mod(plainT, plainT, gr.p);

    mpz_clears(val1, NULL);
}



//******* FAST ***********
// check c0^(x1)c1=1
void verif_damgard_fast(secretK_damgard sk, Cgroup_fast gr, CipherT_short cipherT)
{
  mpz_t val2;
  mpz_init(val2);
  mpz_powm(val2,cipherT.u,sk.x1,gr.p);
  mpz_mul(val2,val2,cipherT.e);
  mpz_mod(val2,val2,gr.p);
  mpz_cmp_ui(val2,1);

  mpz_clear(val2);
}

//dec fast damgard: c2c0^(x2) --> vu^(x2)
void decrypt_damgard_fast(mpz_t plainT, secretK_damgard sk, Cgroup_fast gr, CipherT_short cipherT)
{
  mpz_t v1;
  mpz_init(v1);
  mpz_powm(v1,cipherT.u,sk.x2,gr.p);
  mpz_mul(plainT,cipherT.v,v1);
  mpz_mod(plainT, plainT, gr.p);
  mpz_clear(v1);
}


//********* LINEAR Original Damgard *****************

//verif  u1^(sk1)=c1 & u2^(sk2)=c2
void verif_LD(secretK_LD sk, Cgroup_fast gr, CipherT_LD cipherT)
{
    mpz_t val2;
    mpz_init(val2);
    mpz_powm(val2,cipherT.u1,sk.x1,gr.p);
    mpz_cmp(val2,cipherT.c1);
    mpz_powm(val2,cipherT.u2,sk.x2,gr.p);
    mpz_cmp(val2,cipherT.c2);
    mpz_clear(val2);
}

//dec damgard: c3/(u1.u2)^(sk3)
void decrypt_LD(mpz_t plainT, secretK_LD sk, Cgroup_fast gr, CipherT_LD cipherT)
{
    mpz_t val1;
    mpz_inits(val1, NULL);
    mpz_mul(val1,cipherT.u1,cipherT.u2);
    mpz_mod(val1,val1,gr.p);
    mpz_powm(val1,val1,sk.x3,gr.p);
    mpz_invert(val1, val1,gr.p);
    mpz_mul(plainT,cipherT.c3,val1);
    mpz_mod(plainT, plainT, gr.p);

    mpz_clears(val1, NULL);
}


//********* LINEAR FAST Original Damgard *****************

//verif  u1^(x1).c1=1 & u2^(x2).c2=1
void verif_LD_fast(secretK_LD sk, Cgroup_fast gr, CipherT_LD cipherT)
{
    mpz_t val2;
    mpz_init(val2);
    mpz_powm(val2,cipherT.u1,sk.x1,gr.p);
    mpz_mul(val2,val2,cipherT.c1);
    mpz_mod(val2,val2,gr.p);
    mpz_cmp_ui(val2,1);
    
    mpz_powm(val2,cipherT.u2,sk.x2,gr.p);
    mpz_mul(val2,val2,cipherT.c2);
    mpz_mod(val2,val2,gr.p);
    mpz_cmp_ui(val2,1);
    mpz_clear(val2);
}

//dec damgard: c3.(u1.u2)^(x3)
void decrypt_LD_fast(mpz_t plainT, secretK_LD sk, Cgroup_fast gr, CipherT_LD cipherT)
{
    mpz_t val1;
    mpz_inits(val1, NULL);
    mpz_mul(val1,cipherT.u1,cipherT.u2);
    mpz_mod(val1,val1,gr.p);
    mpz_powm(val1,val1,sk.x3,gr.p);
    mpz_mul(plainT,cipherT.c3,val1);
    mpz_mod(plainT, plainT, gr.p);

    mpz_clears(val1, NULL);
}
