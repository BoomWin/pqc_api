#include "ml_crypto.h"
#include "./ml-kem-512/clean/api.h"
#include "./ml-kem-768/clean/api.h"
#include "./ml-kem-1024/clean/api.h"

#include "./ml-dsa-44/clean/api.h"
#include "./ml-dsa-65/clean/api.h"
#include "./ml-dsa-87/clean/api.h"

/* ML-KEM-512 implementations */
int ml_kem_512_keypair_gen(uint8_t *pk, uint8_t *sk) {

    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
}

int ml_kem_512_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN 이어서 ㄱㄱ 원래 함수보고
}

/*
16진수로 출력 함수
static void printbytes(const uint8_t *x, size_t xlen) {
    size_t i;
    for (i = 0; i < xlen; i++) {
        printf("%02x", x[i]);
    }
    printf("\n");
}

*/