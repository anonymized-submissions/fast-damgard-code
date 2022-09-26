//
//  RandomGenerator.c
//  Cramer-Shoup
//
//  Created by Rokia on 6/6/17.
//  Copyright © 2017 Rokia. All rights reserved.
//

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <time.h>


//generate a prime number of exactly k_bit
void generate_prime_number(gmp_randstate_t generator,mpz_t alea, unsigned int nbr_bit)
{
    int prime;
    mpz_t k;
    mpz_init(k);
    mpz_ui_pow_ui(k,2,nbr_bit-1);
    do
    {
        mpz_urandomb(alea, generator, nbr_bit-1);
        mpz_add(alea,alea,k);
        prime = mpz_probab_prime_p(alea,10);
    }while(prime==0);
    mpz_clear(k);
}

//generate a number of exactly k_bit
void generate_number(gmp_randstate_t generator,mpz_t alea, unsigned int nbr_bit)
{
    mpz_t k;
    mpz_init(k);
    mpz_ui_pow_ui(k,2,nbr_bit-1);
    mpz_urandomb(alea, generator, nbr_bit-1);
    mpz_add(alea,alea,k);
    mpz_clear(k);
}

//generate a number between 2 and p-2
void generate_number_b(gmp_randstate_t generator,mpz_t alea,mpz_t p)
{
    mpz_t val;
    mpz_init(val);
    mpz_sub_ui(val,p,3);
    mpz_urandomm(alea, generator, val);
    //for that the chosen number be between 2 and p-2
    mpz_add_ui(alea,alea,2);

    mpz_clear(val);

}

//generate a number of size half the size of p
void generate_number_half(gmp_randstate_t generator,mpz_t alea,mpz_t p)
{
    size_t sup=0;
    //size of p
    sup=mpz_sizeinbase(p,2);
    sup=sup/2;
    mpz_urandomb(alea, generator, sup);
}

//generate a prime number of exactly k_bit s.t. p - 1 = 2*alea
void generate_sophie_prime_number(gmp_randstate_t generator,mpz_t alea, mpz_t p, unsigned int nbr_bit)
{
    int prime;
    mpz_t k,val1, val2;
    mpz_inits(k,val1, val2, NULL);
    mpz_ui_pow_ui(k,2,nbr_bit-1);
    mpz_sub_ui(val1,p,1);
    do
    {
        mpz_urandomb(alea, generator, nbr_bit-1);
        mpz_add(alea,alea,k);
        prime = mpz_probab_prime_p(alea,10);
        mpz_mul_ui(val2,alea,2);
    }while(prime==0 || mpz_cmp(val1, val2)!= 0);

    mpz_clears(k,val1,val2,NULL);
}


//p is the modulo
void generate(gmp_randstate_t generator,mpz_t alea,mpz_t p,unsigned int nbr, int mthd)
{

    if (mthd==0)
    {
        generate_number(generator,alea,nbr);
    }

    if(mthd==1)
    {
        generate_prime_number(generator,alea,nbr);
    }

    if(mthd==2)
    {
        generate_sophie_prime_number(generator,alea,p,nbr);
    }

    if(mthd==3)
    {
        generate_number_b(generator,alea,p);
    }
    //genrate number half size of p
    if(mthd==4)
    {
        generate_number_half(generator,alea,p);
    }

}
