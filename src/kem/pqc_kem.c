#include "../../include/pqc_kem.h"
#include "ml-kem-512/clean/api.h"
#include "ml-kem-768/clean/api.h"
#include "ml-kem-1024/clean/api.h"

/* ML-KEM-512 implementations */
int ml_kem_512_keypair_gen(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
}

int ml_kem_512_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
}

int ml_kem_512_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* ML-KEM-768 implementations */
int ml_kem_768_keypair_gen(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
}

int ml_kem_768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk);
}

int ml_kem_768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* ML-KEM-1024 implementations */
int ml_kem_1024_keypair_gen(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pk, sk);
}

int ml_kem_1024_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct, ss, pk);
}

int ml_kem_1024_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss, ct, sk);
} 