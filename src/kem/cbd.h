#ifndef PQC_CBD_H
#define PQC_CBD_H

#include "../../include/pqc_params.h"
#include "./ml-kem-512/clean/poly.h"
#include <stdint.h>

void poly_cbd_eta1(poly *r, const uint8_t *buf, PQC_MODE mode);
void poly_cbd_eta2(poly *r, const uint8_t *buf, PQC_MODE mode);

#endif