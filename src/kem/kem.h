#include "../../include/pqc_params.h"
#include "../common/fips202.h"
#include "get_func.h"
#include <stdint.h>

// random keypair for kem
int crypto_kem_keypair(uint8_t *pk, uint8_t *sk, int mode);

// derandom keypair for kem
int crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins, int mode);

// seed-random encrypt for kem
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, int mode);

// seed-derandom encrypt for kem
int crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins, int mode);

//decrypt for kem
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, int mode);



