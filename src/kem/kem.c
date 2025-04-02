#include "indcpa.h"
#include "kem.h"
#include "../common/randombytes.h"
#include "symmetric.h"
#include "verify.h"
#include <stddef.h>
#include <string.h>


int crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins, PQC_MODE mode) {
    size_t indcpa_secretkeybytes, publickeybytes, secretkeybytes;

    indcpa_secretkeybytes = get_mlkem_secretkeybytes(mode);
    publickeybytes = get_mlkem_publickeybytes(mode);
    secretkeybytes = get_mlkem_secretkeybytes(mode);

    if (indcpa_secretkeybytes && publickeybytes && secretkeybytes == 0) {
        pritnf("파라미터 불러오기 error!!!!!");
    }

    // Generate keypair
    indcpa_keypair_derand(pk, sk, coins, mode);

    // Append public key to secret key
    memcpy(sk + indcpa_secretkeybytes, pk, publickeybytes);

    // Append hash of public key to secret key
    hash_h(sk + secretkeybytes - 2 * MLKEM_SYMBYTES, pk, publickeybytes);

    // Value z for pseudo-random output on reject
    memcpy(sk + secretkeybytes - MLKEM_SYMBYTES, coins + MLKEM_SYMBYTES, MLKEM_SYMBYTES);
    return 0;
}

int crypto_kem_keypair(uint8_t *pk, uint8_t *sk, PQC_MODE mode) {
    uint8_t coins[2 * MLKEM_SYMBYTES];
    randombytes(coins, 2 * MLKEM_SYMBYTES);
    crypto_kem_keypair_derand(pk, sk, coins, mode);
    return 0;
}

int crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, 
                            const uint8_t *pk, const uint8_t *coins) {
    
}