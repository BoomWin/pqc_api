#ifndef ML_CRYPTO_H
#define ML_CRYPTO_H

#include <stdint.h>
#include <stddef.h>


/* ML-KEM Functions */
// ML-KEM-512
int ml_kem_512_keypair_gen(uint8_t *pk, uint8_t *sk);
int ml_kem_512_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int ml_kem_512_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// ML-KEM-768
int ml_kem_768_keypair_gen(uint8_t *pk, uint8_t *sk);
int ml_kem_768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int ml_kem_768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// ML-KEM-1024
int ml_kem_1024_keypair_gen(uint8_t *pk, uint8_t *sk);
int ml_kem_1024_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int ml_kem_1024_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
/* ===================================================  */
/* ML-DSA Functions */
// ML-DSA-44
int ml_dsa_44_keypair_gen(uint8_t *pk, uint8_t *sk);
int ml_dsa_44_sign(uint8_t *sig, size_t *sig_len,
                   const uint8_t *msg, size_t msg_len,
                   const uint8_t *sk);
int ml_dsa_44_sign_message(uint8_t *sm, size_t *smlen,
                           const uint8_t *m, size_t mlen,
                           const uint8_t *sk);
int ml_dsa_44_verify(const uint8_t *sig, size_t sig_len, 
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *pk);
// 추가: 서명된 메시지 생성/검증 함수
int ml_dsa_44_open_message(uint8_t *m, size_t *mlen,
                          const uint8_t *sm, size_t smlen,
                          const uint8_t *pk);
// ML-DSA-65
int ml_dsa_65_keypair_gen(uint8_t *pk, uint8_t *sk);
int ml_dsa_65_sign(uint8_t *sig, size_t *sig_len,
                   const uint8_t *msg, size_t msg_len,
                   const uint8_t *sk);
int ml_dsa_65_sign_message(uint8_t *sm, size_t *smlen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk);
int ml_dsa_65_verify(const uint8_t *sig, size_t sig_len,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *pk);

int ml_dsa_65_open_message(uint8_t *m, size_t *mlen,
                          const uint8_t *sm, size_t smlen,
                          const uint8_t *pk);

// ML-DSA-87
// ML-DSA-87
int ml_dsa_87_keypair_gen(uint8_t *pk, uint8_t *sk);
int ml_dsa_87_sign(uint8_t *sig, size_t *sig_len,
                   const uint8_t *msg, size_t msg_len,
                   const uint8_t *sk);
int ml_dsa_87_sign_message(uint8_t *sm, size_t *smlen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk);
int ml_dsa_87_verify(const uint8_t *sig, size_t sig_len,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *pk);
int ml_dsa_87_open_message(uint8_t *m, size_t *mlen,
                          const uint8_t *sm, size_t smlen,
                          const uint8_t *pk);
/* ===================================================  */

/* ===================================================  */
/* Key sizes and other constants */
// ML-KEM-512
#define ML_KEM_512_PUBLIC_KEY_BYTES  800
#define ML_KEM_512_SECRET_KEY_BYTES  1632
#define ML_KEM_512_CIPHERTEXT_BYTES  768
#define ML_KEM_512_CRYPTO_BYTES 32
// #define PQCLEAN_MLKEM512_CLEAN_CRYPTO_ALGNAME "ML-KEM-512"
#define ML_KEM_512_SHARED_SECRET_BYTES 32

// ML-KEM-768
#define ML_KEM_768_PUBLIC_KEY_BYTES  1184
#define ML_KEM_768_SECRET_KEY_BYTES  2400
#define ML_KEM_768_CIPHERTEXT_BYTES  1088
#define ML_KEM_768_SHARED_SECRET_BYTES 32

// ML-KEM-1024
#define ML_KEM_1024_PUBLIC_KEY_BYTES  1568
#define ML_KEM_1024_SECRET_KEY_BYTES  3168
#define ML_KEM_1024_CIPHERTEXT_BYTES  1568
#define ML_KEM_1024_SHARED_SECRET_BYTES 32
/* ===================================================  */
// ML-DSA-44
#define MAXLEN 2048  // 최대 메시지 길이

#define ML_DSA_44_PUBLIC_KEY_BYTES  1312
#define ML_DSA_44_SECRET_KEY_BYTES  2560
#define ML_DSA_44_SIGNATURE_BYTES   2420
#define ML_DSA_44_MAX_SIGNATURE_BYTES (ML_DSA_44_SIGNATURE_BYTES + MAXLEN)

// ML-DSA-65
#define ML_DSA_65_PUBLIC_KEY_BYTES  1952
#define ML_DSA_65_SECRET_KEY_BYTES  4032
#define ML_DSA_65_SIGNATURE_BYTES   3309
#define ML_DSA_65_MAX_SIGNATURE_BYTES (ML_DSA_65_SIGNATURE_BYTES + MAXLEN)

// ML-DSA-87
#define ML_DSA_87_PUBLIC_KEY_BYTES  2592
#define ML_DSA_87_SECRET_KEY_BYTES  4896
#define ML_DSA_87_SIGNATURE_BYTES   4627
#define ML_DSA_87_MAX_SIGNATURE_BYTES (ML_DSA_87_SIGNATURE_BYTES + MAXLEN)
/* ===================================================  */


#endif