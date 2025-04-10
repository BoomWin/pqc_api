#include "polyvec.h"
#include "poly.h"

// mlkem_polyvec_compress

void mlkem_polyvec_compress(uint8_t *r, const polyvec *a, PQC_MODE mode) {
    unsigned int i, j, k;
    uint64_t d0;

    if (mode == PQC_MODE_1 || mode == PQC_MODE_2) {
        // ML-KEM-512/768 : 4개씩 처리, 각 10비트
        uint16_t t[4];
        for (i = 0; i < get_mlkem_k(mode); i++) {
            for (j = 0; j < MLKEM_N / 4; j++) {
                for (k = 0; k < 4; k++) {
                    t[k] = a->vec[i].coeffs[4 * j + k];
                    t[k] += ((int16_t)t[k] >> 15) * MLKEM_Q;

                    d0 = t[k];
                    d0 <<= 10;
                    d0 += 1665;
                    d0 *= 1290167;
                    d0 >>= 32;
                    t[k] = d0 & 0x3ff;
                }

                r[0] = (uint8_t)(t[0] >> 0);
                r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
                r[2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
                r[3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
                r[4] = (uint8_t)(t[3] >> 2);
                r += 5;
            }
        }
    }
    else if (mode == PQC_MODE_3) {
        // ML-KEM-1024 : 8개씩 처리, 각 11비트
        uint16_t t[8];
        for (i = 0; i < get_mlkem_k(mode); i++) {
            for (j = 0; j < MLKEM_N / 8; j++) {
                for (k = 0; k < 8; k++) {
                    t[k] = a->vec[i].coeffs[8 * j + k];
                    t[k] += ((int16_t)t[k] >> 15) & MLKEM_Q;

                    d0 = t[k];
                    d0 <<= 11;
                    d0 += 1664;
                    d0 *= 645084;
                    d0 >>= 31;
                    t[k] = d0 & 0x7ff;
                }

                r[0] = (uint8_t)(t[0] >> 0);
                r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 3));
                r[2] = (uint8_t)((t[1] >> 5) | (t[2] << 6));
                r[3] = (uint8_t)(t[2] >> 2);
                r[4] = (uint8_t)((t[2] >> 10) | (t[3] << 1));
            }
        }
    }
}