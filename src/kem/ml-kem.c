#include "ml-kem.h"

int get_kem_params(PQC_MODE mode, int *k, int *eta1, int *eta2) {
    switch (mode) {
        case PQC_MODE_1:
            *k = MLKEM_512_K;
            *eta1 = MLKEM_512_ETA1;
            *eta2 = MLKEM_512_ETA2;
            break;
        case PQC_MODE_2:
            *k = MLKEM_768_K;
            *eta1 = MLKEM_768_ETA1;
            *eta2 = MLKEM_768_ETA2;
            break;
        case PQC_MODE_3:
            *k = MLKEM_1024_K;
            *eta1 = MLKEM_1024_ETA1;
            *eta2 = MLKEM_1024_ETA2;
            break;
        default:
            return -1;
    }
    return 0;
}

/* MODE에 따라서 동작 다르게 하기 위해 ml_kem_keypair 함수 구현 */

int ml_kem_keypair(uint8_t *pk, uint8_t *sk, PQC_MODE mode) {
    int k, eta1, eta2;
    if (get_kem_params(mode, &k, &eta1, &eta2) != 0) {
        return -1;
    }
    if (mode == PQC_MODE_1) {
        return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
    } else if (mode == PQC_MODE_2) {
        return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
    } else if (mode == PQC_MODE_3) {
        return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pk, sk);
    }
    return -1;
}
