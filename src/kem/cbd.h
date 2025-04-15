#ifndef CBD_H
#define CBD_H


#include "../../include/pqc_params.h"
#include "poly.h"
#include <stdint.h>

void poly_cbd_eta1(poly *r, const uint8_t *buf, int mode);
void poly_cbd_eta2(poly *r, const uint8_t *buf, int mode);

#endif