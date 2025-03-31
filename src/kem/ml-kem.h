#ifndef ML_KEM_H
#define ML_KEM_H

#include "../../include/pqc_params.h"

// ML-KEM 통합 함수들
int ml_kem_keypair_gen(uint8_t *pk, uint8_t *sk ,PQC_MODE mode);
int ml_kem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk, PQC_MODE mode);
int ml_kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, PQC_MODE mode);

// 내부 helper 함수들
int get_kem_params(PQC_MODE mode, int *k, int *eta1, int *eta2);
size_t get_kem_bytes(PQC_MODE mode, size_t *pk_bytes, size_t *sk_bytes, size_t *ct_bytes);

#endif
