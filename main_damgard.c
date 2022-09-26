#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include <time.h>
#include <sys/resource.h>
#include "primitiveRoot.h"
#include "RandomGenerator.h"
#include "keyGenerator.h"
#include "keys.h"
#include "encrypt.h"
#include "decrypt.h"
#include <stdlib.h>


#define NbrTrials 100

int linear_damgard() {
    gmp_randstate_t generator;
    gmp_randinit_default(generator);
    time_t t = time(NULL);
    gmp_randseed_ui(generator,t);

    //sec param
    unsigned int g[] = {512,1024,2048,4096};//,3072,7680,15360};
    // FILE
    FILE* fichier1 = NULL;
    FILE* fichier2 = NULL;
    char *new_str;
    char *new_str2;
    asprintf(&new_str,"%s","time_damgard/ET-std-linear-damgard.txt");
    asprintf(&new_str2,"%s","time_damgard/ET-fast-linear-damgard.txt");
    fichier1 = fopen(new_str, "w+");
    fichier2 = fopen(new_str2, "w+");

    //temp variables for stocking time computations
    long double cG_std=0,cE_std=0,cD_std=0,cV_std=0,cTOT_std=0;
    long double cG_fast=0,cE_fast=0,cD_fast=0,cV_fast=0,cTOT_fast=0;
    clock_t start, end;
    double cputime_used;

    //declaration messages
    mpz_t msg,msgP1,msgP2;
    mpz_inits(msg,msgP1,msgP2,NULL);

    //key generation std
    secretK_LD skv;
    publicK_LD pkv;
    CipherT_LD civ;

    mpz_inits(skv.x1,skv.x2,skv.x3,pkv.pk1,pkv.pk2,pkv.pk3,civ.u1,civ.u2,civ.c1,civ.c2,civ.c3,NULL);

    //key generation fast
    secretK_LD skf;
    publicK_LD_fast pkf;
    Cgroup_fast grf;
    CipherT_LD cif;
    mpz_inits(skf.x1,skf.x2,skf.x3,pkf.b0,pkf.b1,pkf.b2,pkf.b3,grf.p,grf.q,grf.gen1,cif.u1,cif.u2,cif.c1,cif.c2,cif.c3,NULL);

    // for p prime used in all protocols.
    Cgroup_fast gr_glo;
    mpz_inits(gr_glo.p,gr_glo.q,gr_glo.gen1,NULL);



  for(int i = 0; i < 4; i++)
  {
    cG_std=0;cE_std=0;cV_std=0;cD_std=0;cTOT_std=0;
    cG_fast=0;cE_fast=0;cV_fast=0;cD_fast=0;cTOT_fast=0;
    for(int j = 0; j < NbrTrials; j++)
    {
      float progression = (float)(( i * NbrTrials ) + j) /  (float) (4 * NbrTrials) * 100;
      printf("Fast: Iteration %d -- \tTrial %d -- Progress: %.2f/100\n", i, j, progression);
      //p prime for all protocols
      generate(generator,gr_glo.p,NULL,g[i], 1);
      //msg to encrypt
      //size of message is the same as group size - 2
      // does not work if message is too large
      generate(generator,msg, NULL,g[i]-2,0);

      // ************FAST***************
      //key generation
      start= clock();
      keyGenerator_LD_fast(generator,&gr_glo,&skf,&pkf,&grf,g[i]);
      end = clock();
      cputime_used = ((double) (end - start)) / CLOCKS_PER_SEC;
      cG_fast+=cputime_used;
      //encrypt
      start = clock();
      encrypt_LD_fast(generator,&cif,pkf,grf,msg);
      end = clock();
      cputime_used = ((double) (end - start)) / CLOCKS_PER_SEC;
      cE_fast+=cputime_used;

      start = clock();
      verif_LD_fast(skf,grf,cif);
      end = clock();
      cputime_used = ((double) (end - start)) / CLOCKS_PER_SEC;
      cV_fast+=cputime_used;


      start = clock();
      decrypt_LD_fast(msgP2,skf,grf,cif);
      end = clock();
      cputime_used = ((double) (end - start)) / CLOCKS_PER_SEC;
      cD_fast+=cputime_used;

      //if(mpz_cmp(msgP2,msg)==0){printf("fast linear OOKKK\n");}
      // ************* END FAST *************************
      // ************STD3 VARIANT***************
      //key generation
      start= clock();
      keyGenerator_LD(generator,&gr_glo,&skv,&pkv,&grf,g[i]);
      end = clock();
      cputime_used = ((double) (end - start)) / CLOCKS_PER_SEC;
      cG_std+=cputime_used;

      //encrypt
      start = clock();
      encrypt_LD(generator,&civ,pkv,grf,msg);
      end = clock();
      cputime_used = ((double) (end - start)) / CLOCKS_PER_SEC;
      cE_std+=cputime_used;


      start = clock();
      verif_LD(skv,grf,civ);
      end = clock();
      cputime_used = ((double) (end - start)) / CLOCKS_PER_SEC;
      cV_std+=cputime_used;


      start = clock();
      decrypt_LD(msgP1,skv,grf,civ);
      end = clock();
      cputime_used = ((double) (end - start)) / CLOCKS_PER_SEC;
      cD_std+=cputime_used;


      //if(mpz_cmp(msgP1,msg)==0){printf("---------linear damgard OOKKK\n");}
     // ************* END STD3 VARIANT *************************



    }
    cTOT_std=cD_std+cV_std;
    cTOT_fast=cV_fast+cD_fast;

    fprintf(fichier1, "%d %Lf %Lf %Lf %Lf %Lf\n", g[i],cG_std/NbrTrials,cE_std/NbrTrials,cD_std/NbrTrials,cV_std/NbrTrials,cTOT_std/NbrTrials);
    fflush(fichier1);

    fprintf(fichier2, "%d %Lf %Lf %Lf %Lf %Lf\n", g[i],cG_fast/NbrTrials,cE_fast/NbrTrials,cD_fast/NbrTrials,cV_fast/NbrTrials,cTOT_fast/NbrTrials);
    fflush(fichier2);

  }
      fclose(fichier1);
      fclose(fichier2);

      mpz_clears(msg,msgP1,msgP2,NULL);
      mpz_clears(skv.x1,skv.x2,skv.x3,pkv.pk1,pkv.pk2,pkv.pk3,civ.u1,civ.u2,civ.c1,civ.c2,civ.c3,NULL);
      mpz_inits(skf.x1,skf.x2,skf.x3,pkf.b0,pkf.b1,pkf.b2,pkf.b3,grf.p,grf.q,grf.gen1,cif.u1,cif.u2,cif.c1,cif.c2,cif.c3,NULL);
      mpz_clears(gr_glo.p,gr_glo.q,gr_glo.gen1,NULL);
      gmp_randclear(generator);
      return 0;
}


int std_damgard() {
    gmp_randstate_t generator;
    gmp_randinit_default(generator);
    time_t t = time(NULL);
    gmp_randseed_ui(generator,t);

    //sec param
    unsigned int g[] = {512,1024,2048,4096};//,3072,7680,15360};
    // FILE
    FILE* fichier1 = NULL;
    FILE* fichier2 = NULL;
    char *new_str;
    char *new_str2;
    asprintf(&new_str,"%s","time_damgard/ET-std-damgard.txt");
    asprintf(&new_str2,"%s","time_damgard/ET-fast-damgard.txt");
    fichier1 = fopen(new_str, "w+");
    fichier2 = fopen(new_str2, "w+");

    //temp variables for stocking time computations
    long double cG_std=0,cE_std=0,cD_std=0,cV_std=0,cTOT_std=0;
    long double cG_fast=0,cE_fast=0,cD_fast=0,cV_fast=0,cTOT_fast=0;
    clock_t start, end;
    double cputime_used;

    //declaration messages
    mpz_t msg,msgP1,msgP2;
    mpz_inits(msg,msgP1,msgP2,NULL);

    //key generation std
    secretK_damgard skv;
    publicK_damgard pkv;
    CipherT_short civ;

    mpz_inits(skv.x1,skv.x2,pkv.pk1,pkv.pk2,civ.e,civ.u,civ.v,NULL);

    //key generation fast
    secretK_damgard skf;
    publicK pkf;
    Cgroup_fast grf;
    CipherT_short cif;
    mpz_inits(skf.x1,skf.x2,pkf.c,pkf.d,pkf.h,grf.p,grf.q,grf.gen1,cif.u,cif.e,cif.v,NULL);

    // for p prime used in all protocols.
    Cgroup_fast gr_glo;
    mpz_inits(gr_glo.p,gr_glo.q,gr_glo.gen1,NULL);



  for(int i = 0; i < 4; i++)
  {
    cG_std=0;cE_std=0;cV_std=0;cD_std=0;cTOT_std=0;
    cG_fast=0;cE_fast=0;cV_fast=0;cD_fast=0;cTOT_fast=0;
    for(int j = 0; j < NbrTrials; j++)
    {
      float progression = (float)(( i * NbrTrials ) + j) /  (float) (4 * NbrTrials) * 100;
       printf("STD: Iteration %d -- \tTrial %d -- Progress: %.2f/100\n", i, j, progression);
      //p prime for all protocols
      generate(generator,gr_glo.p,NULL,g[i], 1);
      //msg to encrypt
      //size of message is the same as group size - 2
      // does not work if message is too large
      generate(generator,msg, NULL,g[i]-2,0);

      // ************FAST***************
      //key generation
      start= clock();
      keyGenerator_damgard_fast(generator,&gr_glo,&skf,&pkf,&grf,g[i]);
      end = clock();
      cputime_used = ((double) (end - start)) / CLOCKS_PER_SEC;
      cG_fast+=cputime_used;
      //encrypt
      start = clock();
      encrypt_damgard_fast(generator,&cif,pkf,grf,msg);
      end = clock();
      cputime_used = ((double) (end - start)) / CLOCKS_PER_SEC;
      cE_fast+=cputime_used;

      start = clock();
      verif_damgard_fast(skf,grf,cif);
      end = clock();
      cputime_used = ((double) (end - start)) / CLOCKS_PER_SEC;
      cV_fast+=cputime_used;

      
      start = clock();
      decrypt_damgard_fast(msgP2,skf,grf,cif);
      end = clock();
      cputime_used = ((double) (end - start)) / CLOCKS_PER_SEC;
      cD_fast+=cputime_used;
      
      if(mpz_cmp(msgP2,msg)!=0){
        printf("Fast correctness error");
        exit(1);
      }
      // ************* END FAST *************************
      // ************STD3 VARIANT***************
      //key generation
      start= clock();
      keyGenerator_damgard(generator,&gr_glo,&skv,&pkv,&grf,g[i]);
      end = clock();
      cputime_used = ((double) (end - start)) / CLOCKS_PER_SEC;
      cG_std+=cputime_used;

      //encrypt
      start = clock();
      encrypt_damgard(generator,&civ,pkv,grf,msg);
      end = clock();
      cputime_used = ((double) (end - start)) / CLOCKS_PER_SEC;
      cE_std+=cputime_used;


      start = clock();
      verif_damgard(skv,grf,civ);
      end = clock();
      cputime_used = ((double) (end - start)) / CLOCKS_PER_SEC;
      cV_std+=cputime_used;

      
      start = clock();
      decrypt_damgard(msgP1,skv,grf,civ);
      end = clock();
      cputime_used = ((double) (end - start)) / CLOCKS_PER_SEC;
      cD_std+=cputime_used;


      if(mpz_cmp(msgP1,msg)!=0){
        printf("Damgard correctness error");
        exit(1);
      }
     // ************* END STD3 VARIANT *************************



    }
    cTOT_std=cD_std+cV_std;
    cTOT_fast=cV_fast+cD_fast;

    fprintf(fichier1, "%d %Lf %Lf %Lf %Lf %Lf\n", g[i],cG_std/NbrTrials,cE_std/NbrTrials,cD_std/NbrTrials,cV_std/NbrTrials,cTOT_std/NbrTrials);
    fflush(fichier1);

    fprintf(fichier2, "%d %Lf %Lf %Lf %Lf %Lf\n", g[i],cG_fast/NbrTrials,cE_fast/NbrTrials,cD_fast/NbrTrials,cV_fast/NbrTrials,cTOT_fast/NbrTrials);
    fflush(fichier2);

  }
      fclose(fichier1);
      fclose(fichier2);

      mpz_clears(msg,msgP1,msgP2,NULL);
      mpz_clears(skv.x1,skv.x2,pkv.pk1,pkv.pk2,civ.e,civ.u,civ.v,NULL);
      mpz_clears(skf.x1,skf.x2,pkf.c,pkf.d,pkf.h,grf.p,grf.q,grf.gen1,cif.u,cif.e,cif.v,NULL);
      mpz_clears(gr_glo.p,gr_glo.q,gr_glo.gen1,NULL);
      gmp_randclear(generator);
      return 0;
}


int main() {
  std_damgard();
  linear_damgard();
  return EXIT_SUCCESS;
}