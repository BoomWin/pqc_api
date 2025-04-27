#ifndef INDCPA_H
#define INDCPA_H

#include <stdio.h>
#include "../../include/pqc_params.h"
#include "polyvec.h"

void gen_matrix(polyvec *a, const uint8_t *seed, int transposed, int mode);

void indcpa_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins, int mode);

void indcpa_enc(uint8_t *c, const uint8_t *m, const uint8_t *pk,
                const uint8_t *coins, int mode);   

void indcpa_dec(uint8_t *m, const uint8_t *c, const uint8_t *sk, int mode);

#endif