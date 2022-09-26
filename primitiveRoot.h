//
//  primitiveRoot.h
//  Cramer-Shoup
//
//  Created by Rokia on 6/6/17.
//  Copyright © 2017 Rokia. All rights reserved.
//

#ifndef primitiveRoot_h
#define primitiveRoot_h

#include <stdio.h>
#include <gmp.h>

void primitiveRoot_g(gmp_randstate_t generator,mpz_t p,mpz_t g1, mpz_t g2);
void primitiveRoot_g_fast(gmp_randstate_t generator,mpz_t p,mpz_t g1);
#endif /* primitiveRoot_h */
