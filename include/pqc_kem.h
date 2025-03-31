#ifndef PQC_KEM_H
#define PQC_KEM_H

#include "pqc_params.h"
#include <stdint.h>



/* ML-KEM-512 */
int ml_kem_512_keypair_gen(uint8_t *pk, uint8_t *sk);
int ml_kem_512_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int ml_kem_512_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* ML-KEM-768 */
int ml_kem_768_keypair_gen(uint8_t *pk, uint8_t *sk);
int ml_kem_768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int ml_kem_768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* ML-KEM-1024 */
int ml_kem_1024_keypair_gen(uint8_t *pk, uint8_t *sk);
int ml_kem_1024_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int ml_kem_1024_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif