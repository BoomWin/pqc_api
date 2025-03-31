#include "cbd.h"

static uint32_t load32_littleendian(const uint8_t x[4]) {
    uint32_t r;
    r = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    r |= (uint32_t)x[3] << 24;
    return r;
}

static uint32_t load24_littleendian(const uint8_t x[3]) {
    uint32_t r;
    r = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    return r;
}

static void cbd2(poly *r, const uint8_t *buf) {
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;

    for (i = 0; i < MLKEM_N / 8; i++) {
        t = load32_littleendian(buf + 4 * i);
        d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        for (j = 0; j < 8; j++) {
            a = (d >> (4 * j + 0)) & 0x3;
            b = (d >> (4 * j + 1)) & 0x3;
            r->coeffs[8 * i + j] = a - b;
        }
    }
}

static void cbd3(poly *r, const uint8_t *buf) {
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;

    for (i = 0; i < MLKEM_N / 4; i++) {
        t = load32_littleendian(buf + 3 * i);
        d = t & 0x00249249;
        d += (t >> 1) & 0x00249249;
        d += (t >> 2) & 0x00249249;

        for (j = 0; j < 4; j++) {
            a = (d >> (6 * j + 0)) & 0x7;
            b = (d >> (6 * j + 3)) & 0x7;
            r->coeffs[4 * i + j] = a - b;
        }
    }
}

void poly_cbd_eta1(poly *r, const uint8_t *buf, PQC_MODE mode) {
    switch (mode) {
        case PQC_MODE_1:    // ML-KEM-512
            cbd3(r, buf);
            break;
        case PQC_MODE_2: // ML-KEM-768
        case PQC_MODE_3: // ML-KEM-1024
            cbd2(r, buf);
            break;
        default:
            // 에러처리
            break;
    }
    return 0;
}

void poly_cbd_eta2(poly *r, const uint8_t *buf, PQC_MODE mode) {
    cbd2(r, buf); // 모든 보안레벨에서 eta2=2 사용
}