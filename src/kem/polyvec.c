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

void mlkem_polyvec_decompress(polyvec *r, const uint8_t *a, PQC_MODE mode) {
    unsigned int i, j, k;

    if (mode == PQC_MODE_1 || mode == PQC_MODE_2) {
        // ML-KEM-512/768 : 4개씩 처리, 각 10비트
        uint16_t t[4];
        for (i = 0; i < get_mlkem_k(mode); i++) {
            for (j = 0; j < MLKEM_N / 4; j++) {
                t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
                t[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
                t[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
                t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
                a+=5;

                for (k = 0; k < 4; k++) {
                    r->vec[i].coeffs[4 * j + k] = ((uint32_t)(t[k] & 0x3FF) * MLKEM_Q + 512) >> 10;
                }
            }
        }
    }
    else if (mode == PQC_MODE_3) {
        // ML-KEM-1024 : 11비트, 8개씩 처리
        uint16_t t[8];
        for (i = 0; i < get_mlkem_k(mode); i++) {
            for (j = 0; j < MLKEM_N / 8; j++) {
                t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
                t[1] = (a[1] >> 3) | ((uint16_t)a[2] << 5);
                t[2] = (a[2] >> 6) | ((uint16_t)a[3] << 2) | ((uint16_t)a[4] << 10);
                t[3] = (a[4] >> 1) | ((uint16_t)a[5] << 7);
                t[4] = (a[5] >> 4) | ((uint16_t)a[6] << 4);
                t[5] = (a[6] >> 7) | ((uint16_t)a[7] << 1) | ((uint16_t)a[8] << 9);
                t[6] = (a[8] >> 2) | ((uint16_t)a[9] << 6);
                t[7] = (a[9] >> 5) | ((uint16_t)a[10] << 3);
                a += 11;

                for (k = 0; k < 8; k++) {
                    r->vec[i].coeffs[8 * j + k] = ((uint32_t)(t[k] & 0x7FF) * MLKEM_Q + 1024) >> 11;
                }
            }
        }
    }
}

void mlkem_polyvec_tobytes(uint8_t *r, const polyvec *a, PQC_MODE mode) {
    unsigned int i;
    size_t k;

    k = get_mlkem_k(mode);

    for (i = 0; i < k; i++) {
        mlkem_poly_tobytes(r + i * MLKEM_POLYBYTES, &a->vec[i], mode);
    }
}

void mlkem_polyvec_frombytes(polyvec *r, const uint8_t *a, PQC_MODE mode) {
    unsigned int i;
    size_t k;

    k = get_mlkem_k(mode);

    for (i = 0; i < k; i++) {
        mlkem_poly_frombytes(&r->vec[i], a + i * MLKEM_POLYBYTES, mode);
    }
}

void mlkem_polyvec_ntt(polyvec *r, PQC_MODE mode) {
    unsigned int i;
    size_t k;

    k = get_mlkem_k(mode);

    for (i = 0; i < k; i++) {
        mlkem_poly_ntt(&r->vec[i], mode);
    }
}

void mlkem_polyvec_invntt_tomont(polyvec *r, PQC_MODE mode) {
    unsigned int i;
    size_t k;

    k = get_mlkem_k(mode);

    for (i = 0; i < k; i++) {
        mlkem_poly_invntt_tomont(&r->vec[i], mode);
    }
}

void mlkem_polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b, PQC_MODE mode) {
    unsigned int i;
    size_t k;
    poly t;

    k = get_mlkem_k(mode);

    if (k == 0) return; // 오류 케이스

    mlkem_poly_basemul_montgomery(r, &a->vec[0], &b->vec[0], mode);

    for (i = 1; i < k; i++) {
        mlkem_poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i], mode);
        mlkem_poly_add(r, r, &t, mode);
    }
    mlkem_poly_reduce(r, mode);
}

void mlkem_polyvec_reduce(polyvec *r, PQC_MODE mode) {
    unsigned int i;
    size_t k;

    k = get_mlkem_k(mode);

    for (i = 0; i < k; i++) {
        mlkem_poly_reduce(&r->vec[i], mode);
    }
}

void mlkem_polyvec_add(polyvec *r, const polyvec *a, const polyvec *b, PQC_MODE mode) {
    unsigned int i;
    size_t k;

    k = get_mlkem_k(mode);

    for (i = 0; i < k; i++) {
        mlkem_poly_add(&r->vec[i], &a->vec[i], &b->vec[i], mode);
    }
 }