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


// get_polyvecbytes 등 필요한 helper 함수들 구현
static size_t get_polyvecbytes(PQC_MODE mode) {
    switch (mode) {
        case PQC_MODE_1:
            return MLKEM_512_POLYVECBYTES;
            break;
        case PQC_MODE_2:
            return MLKEM_768_POLYVECBYTES;
            break;
        case PQC_MODE_3:
            return MLKEM_1024_POLYVECBYTES;
            break;
        default:
            return 0;
    }
}

// get_polyveccompressbytes 등 필요한 helper 함수들 구현 
static size_t get_polyveccompressbytes(PQC_MODE mode) {
    switch (mode) {
        case PQC_MODE_1:
            return MLKEM_512_POLYVECCOMPRESSEDBYTES;
        case PQC_MODE_2:
            return MLKEM_768_POLYVECCOMPRESSEDBYTES;
        case PQC_MODE_3:
            return MLKEM_1024_POLYVECCOMPRESSEDBYTES;
    }
}


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

static void pack_ciphertext(uint8_t *r, polyvec *b, poly *v, PQC_MODE mode) {
    polyvec_compress(r, b, mode);
    poly_compress(r + get_polyveccompressbytes(mode), v);
}

static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t *c, PQC_MODE mode) {
    polyvec_decompress(b, c, mode);
    poly_decompress(v, c + get_polyveccompressbytes(mode));
}


static unsigned int rej_uniform(int16_t *r, 
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen) {
    unsigned int ctr, pos;
    uint16_t val0, val1;

    ctr = 0;
    pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
        val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
        pos += 3;

        if (val0 < MLKEM_Q) {
            r[ctr++] = val0;
        }
        if (ctr < len && val1 < MLKEM_Q) {
            r[ctr++] = val1;
        }
    }
    return ctr;
}
// gen_a, gen_at 그냥 matrix에 mode 받아서 그거 에맞게 처리한느 로직으로 구현하면될듯. 

#define GEN_MATRIX_NBLOCKS ((12*MLKEM_N/8*(1 << 12)/MLKEM_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)

void gen_matrix(polyvec *a, const uint8_t *seed, int transposed, PQC_MODE mode) {
    unsigned int ctr, i, j, k;
    unsigned int buflen;
    uint8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES];
}