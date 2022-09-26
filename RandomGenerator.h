//
//  RandomGenerator.h
//  Cramer-Shoup
//
//  Created by Rokia on 6/6/17.
//  Copyright © 2017 Rokia. All rights reserved.
//

#ifndef RandomGenerator_h
#define RandomGenerator_h

#include <gmp.h>

void generate(gmp_randstate_t generator,mpz_t alea,mpz_t p,unsigned int nbr, int mthd);

#endif /* RandomGenerator_h */
