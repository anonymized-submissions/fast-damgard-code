#ifndef keys_h
#define keys_h
#include <gmp.h>

struct secretK {
    mpz_t x1;
    mpz_t x2;
    mpz_t y1;
    mpz_t y2;
    mpz_t z1;
    mpz_t z2;
};

typedef struct secretK secretK;

struct secretK_variant {
    mpz_t x;
    mpz_t y;
    mpz_t z;
    mpz_t w;
};

typedef struct secretK_variant secretK_variant;

struct secretK_short {
    mpz_t s;
    mpz_t a;
    mpz_t b;
    mpz_t ap;
    mpz_t bp;
};

typedef struct secretK_short secretK_short;


struct publicK {
    mpz_t c;
    mpz_t d;
    mpz_t h;
};

typedef struct publicK publicK;


struct Cgroup{
    mpz_t p;
    mpz_t q;
    mpz_t g1;
    mpz_t g2;
};

typedef struct Cgroup Cgroup;

struct CipherT{
    mpz_t u1;
    mpz_t u2;
    mpz_t e;
    mpz_t v;
};

typedef struct CipherT CipherT;

struct secretK_fast {
    //mpz_t k;
    mpz_t quo;
    mpz_t s;
    mpz_t t;
    mpz_t x;
    mpz_t y;
    //mpz_t z;
};

typedef struct secretK_fast secretK_fast;

struct publicK_fast {
    mpz_t g1;//g^s
    mpz_t c;
    mpz_t d;
    mpz_t h;
};

typedef struct publicK_fast publicK_fast;

//same for fast LCS
struct Cgroup_fast{
    mpz_t p;
    mpz_t q;
    mpz_t gen1;
};

typedef struct Cgroup_fast Cgroup_fast;



struct CipherT_fast{
    mpz_t u1;
    mpz_t u2;
    mpz_t e;
    mpz_t v;
};

typedef struct CipherT_fast CipherT_fast;

struct CipherT_short{
    mpz_t u;
    mpz_t e;
    mpz_t v;
};

typedef struct CipherT_short CipherT_short;

//Linear Cramer Shoup, same for short linear
struct Cgroup_LCS{
    mpz_t p;
    mpz_t q;
    mpz_t g1;
    mpz_t g2;
    mpz_t g3;
};

typedef struct Cgroup_LCS Cgroup_LCS;

//, same for short linear
struct publicK_LCS {
    mpz_t c1;
    mpz_t c2;
    mpz_t d1;
    mpz_t d2;
    mpz_t h1;
    mpz_t h2;
};

typedef struct publicK_LCS publicK_LCS;

struct secretK_LCS {
    mpz_t x1;
    mpz_t x2;
    mpz_t x3;
    mpz_t y1;
    mpz_t y2;
    mpz_t y3;
    mpz_t z1;
    mpz_t z2;
    mpz_t z3;
};

typedef struct secretK_LCS secretK_LCS;

//same for fast LCS
struct CipherT_LCS{
    mpz_t u1;
    mpz_t u2;
    mpz_t u3;
    mpz_t e;
    mpz_t v;
};

typedef struct CipherT_LCS CipherT_LCS;

//Fast LCS
struct publicK_FLCS {
    mpz_t g1;//g^s1
    mpz_t g2;//g^s2
    mpz_t g3;//g
    mpz_t c1;
    mpz_t c2;
    mpz_t d1;
    mpz_t d2;
    mpz_t h1;
    mpz_t h2;
};

typedef struct publicK_FLCS publicK_FLCS;

struct secretK_FLCS {
    mpz_t x1;
    mpz_t x2;
    mpz_t y1;
    mpz_t y2;
    mpz_t q1;
    mpz_t q2;
    mpz_t t1;
    mpz_t t2;
};

typedef struct secretK_FLCS secretK_FLCS;

//other version
struct secretK_FLCS_3 {
    mpz_t x1;
    mpz_t x2;
    mpz_t x3;
    mpz_t y1;
    mpz_t y2;
    mpz_t y3;
    mpz_t q1;
    mpz_t q2;
    mpz_t q3;
    mpz_t t1;
    mpz_t t2;
    mpz_t t3;
    mpz_t s1;
    mpz_t s2;
    mpz_t s3;
};

typedef struct secretK_FLCS_3 secretK_FLCS_3;

// SHORT Linear
struct secretK_LCS_short {
    mpz_t s1;
    mpz_t s2;
    mpz_t a1;
    mpz_t a2;
    mpz_t ap1;
    mpz_t ap2;
    mpz_t b1;
    mpz_t b2;
    mpz_t bp1;
    mpz_t bp2;
};

typedef struct secretK_LCS_short secretK_LCS_short;

struct secretK_damgard {
    mpz_t x1;
    mpz_t x2;
};

typedef struct secretK_damgard secretK_damgard;

struct publicK_damgard {
    mpz_t pk1;
    mpz_t pk2;
};

typedef struct publicK_damgard publicK_damgard;

// Linear Damgard ---------------------------------------
struct secretK_LD {
    mpz_t x1;
    mpz_t x2;
    mpz_t x3;
};

typedef struct secretK_LD secretK_LD;

struct publicK_LD {
    mpz_t pk1;
    mpz_t pk2;
    mpz_t pk3;
};

typedef struct publicK_LD publicK_LD;

struct publicK_LD_fast {
    mpz_t b0;
    mpz_t b1;
    mpz_t b2;
    mpz_t b3;
};

typedef struct publicK_LD_fast publicK_LD_fast;


struct CipherT_LD{
    mpz_t u1;
    mpz_t u2;
    mpz_t c1;
    mpz_t c2;
    mpz_t c3;
};

typedef struct CipherT_LD CipherT_LD;

// END Linear Damgard ---------------------------------------
#endif /* keys_h */
