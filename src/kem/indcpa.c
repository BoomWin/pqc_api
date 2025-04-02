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
#include "get_func.h"


static void pack_pk(uint8_t *r, polyvec *pk, const uint8_t *seed, PQC_MODE mode) {
    polyvec_tobytes(r, pk, mode);
    memcpy(r + get_mlkem_polyvecbytes(mode), seed, MLKEM_SYMBYTES);
}

static void unpack_pk(polyvec *pk, uint8_t *seed, const uint8_t *packedpk, PQC_MODE mode) {
    polyvec_frombytes(pk, packedpk, mode);
    memcpy(seed, packedpk + get_mlkem_polyvecbytes(mode), MLKEM_SYMBYTES);
}

static void pack_sk(uint8_t *r, polyvec *sk, PQC_MODE mode) {
    polyvec_tobytes(r, sk, mode);
}

static void unpack_sk(polyvec *sk, const uint8_t *packedsk, PQC_MODE mode) {
    polyvec_frombytes(sk, packedsk, mode);
}

static void pack_ciphertext(uint8_t *r, polyvec *b, poly *v, PQC_MODE mode) {
    polyvec_compress(r, b, mode);
    poly_compress(r + get_mlkem_polyveccompressedbytes(mode), v);
}

static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t *c, PQC_MODE mode) {
    polyvec_decompress(b, c, mode);
    poly_decompress(v, c + get_mlkem_polyveccompressedbytes(mode));
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


// transposed=0일 때 원래 A 행렬 생성 (gen_a에 해당)
// transposed=1일 때 A의 전치 행렬 생성 (gen_at에 해당)
void gen_matrix(polyvec *a, const uint8_t *seed, int transposed, PQC_MODE mode) {
    unsigned int ctr, i, j, k;
    unsigned int buflen;
    uint8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES];
    xof_state state;

    int params_k;
    params_k = get_mlkem_k(mode);
    if(params_k == 0) {
        printf("k_params 불러오기 error 입니다.");
    }

    for (i = 0; i < k; i++) {
        for (j = 0; j < k; j++) {
            if (transposed) {
                xof_absorb(&state, seed, (uint8_t)i, (uint8_t)j);
            }
            else {
                xof_absorb(&state, seed, (uint8_t)j, (uint8_t)i);
            }

            xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
            buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            ctr = rej_uniform(a[i].vec[j].coeffs, MLKEM_N, buf, buflen);

            while (ctr < MLKEM_N) {
                xof_squeezeblocks(buf, 1, &state);
                buflen = XOF_BLOCKBYTES;
                ctr += rej_uniform(a[i].vec[j].coeffs + ctr, MLKEM_N - ctr, buf, buflen);
            }
            xof_ctx_release(&state);
        }
    }
}

void indcpa_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins, PQC_MODE mode) {
    unsigned int i;
    uint8_t buf[2 * MLKEM_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + MLKEM_SYMBYTES;
    uint8_t nonce = 0;
    // 최대 k가 4인 것을 고려함.
    polyvec a[4];
    polyvec e, pkpv, skpv;
    int params_k;
    params_k = get_mlkem_k(mode);
    if(params_k == 0) {
        printf("k_params 불러오기 error 입니다.");
    }

    // Initialize seeds
    memcpy(buf, coins, MLKEM_SYMBYTES);
    buf[MLKEM_SYMBYTES] = params_k;
    hash_g(buf, buf, MLKEM_SYMBYTES + 1);

    // Generate Matrix A
    gen_matrix(a, publicseed, 0, mode);

    // Generate secret and error polynomials
    for (i = 0; i < params_k; i++) {
        // 파라미터 겟이 아니라, poly.c에 구현해야하는 부분이다.
        poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++, mode);
    }

    for (i = 0; i < params_k; i++) {
        poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++, mode);
    }

    // NTT transformation
    polyvec_ntt(&skpv, mode);
    polyvec_ntt(&e, mode);

    // Matrix multiplication
    for (i = 0; i < params_k; i++) {
        polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv, mode);
        poly_tomont(&pkpv.vec[i], mode);
    }

    polyvec_add(&pkpv, &pkpv, &e, mode);
    polyvec_reduce(&pkpv, mode);

    // Pack keys
    pack_sk(sk, &skpv, mode);
    pack_pk(pk, &pkpv, publicseed, mode);
        
}

void indcpa_enc(uint8_t *c, const uint8_t *m, const uint8_t *pk, const uint8_t *coins, PQC_MODE mode) {
    unsigned int i;
    uint8_t seed[MLKEM_SYMBYTES];
    uint8_t nonce = 0;
    polyvec sp, pkpv, ep, at[4], b; // 최대 k=4 고려
    poly v, k, epp;
    int params_k;


    params_k = get_mlkem_k(mode);

    if (params_k == 0) {
        printf("파라미터 K 불러오기 Error !!!!")
    }

    // Unpack public key
    unpack_pk(&pkpv, seed, pk, mode);

    // Convert message to polynomial
    poly_frommsg(&k, m, mode);

    // Generate transpose of matrix A
    gen_matrix(at, seed, 1, mode);

    // Generate secret polynomials
    for (i = 0; i < params_k; i++) {
        poly_getnoise_eta1(sp.vec + i, coins, nonce++, mode);
    }
    for (i = 0; i < params_k; i++) {
        poly_getnoise_eta2(ep.vec + i, coins, nonce++, mode);
    }
    
    // Generate error polynomials
    poly_getnoise_eta2(&epp, coins, nonce++, mode);

    // transform to NTT domain
    polyvec_ntt(&sp, mode);

    // Matrix-vector multiplication for b
    for (i = 0; i < params_k; i++) {
        polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp, mode);
    }

    // Vector-vector multiplication for v
    polyvec_basemul_acc_montgomery(&v, &pkpv, &sp, mode);

    // Transform back from NTT domain
    polyvec_invntt_tomont(&b, mode);
    poly_invntt_tomont(&v, mode);

    // Add errors and message
    polyvec_add(&b, &b, &ep, mode);
    poly_add(&v, &v, &epp, mode);
    poly_add(&v, &v, &k, mode);

    // Reduce modulo q
    polyvec_reduce(&b, mode);
    poly_reduce(&v, mode);

    // Pack the ciphertext
    pack_ciphertext(c, &b, &v, mode);
}

void indcpa_dec(uint8_t *m, const uint8_t *c, const uint8_t *sk, PQC_MODE mode) {
    polyvec b, skpv;
    poly v, mp;
    int params_k;

    // Unpack ciphertext and secret key
    unpack_ciphertext(&b, &v, c, mode);
    unpack_sk(&skpv, sk, mode);

    // Transform to NTT domain
    polyvec_ntt(&b, mode);
    polyvec_basemul_acc_montgomery(&mp, &skpv, &b, mode);

    // Transform back from NTT domain
    poly_invntt_tomont(&mp, mode);

    // Subtract to recover message polynomial
    poly_sub(&mp, &v, &mp, mode);
    
    // Reduce modulo q
    poly_reduce(&mp, mode);

    // Convert polynomial to message
    poly_tomsg(m, &mp, mode);
}