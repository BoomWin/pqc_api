#include "indcpa.h"
#include "ntt.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void pack_pk(uint8_t *r, polyvec *pk, const uint8_t *seed, PQC_MODE mode) {
    polyvec_tobytes(r, pk, mode);
    memcpy(r + get_polyvecbytes(mode), seed, MLKEM_SYMBYTES);
}

static void unpack_pk(polyvec *pk, uint8_t *seed, const uint8_t *packedpk, PQC_MODE mode) {
    polyvec_frombytes(pk, packedpk, mode);
    memcpy(seed, packedpk + get_polyvecbytes(mode), MLKEM_SYMBYTES);
}

static void pack_sk(uint8_t *r, polyvec *sk, PQC_MODE mode) {
    polyvec_tobytes(r, sk, mode);
}

static void unpack_sk(polyvec *sk, const uint8_t *packedsk, PQC_MODE mode) {
    polyvec_frombytes(sk, packedsk, mode);
}

// get_polyvecbytes 등 필요한 helper 함수들 구현
static size_t get_polyvecbytes(PQC_MODE mode) {
    switch (mode) {
        case PQC_MODE_1:
            return MLKEM_512_POLYVECBYTES;
        case PQC_MODE_2:
            return MLKEM_768_POLYVECBYTES;
        case PQC_MODE_3:
            return MLKEM_1024_POLYVECBYTES;
        default:
            return 0;
    }
}