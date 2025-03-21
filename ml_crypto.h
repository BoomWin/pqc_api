#ifndef ML_CRYPTO_H
#define ML_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* ===================================================  */
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
/* SPHINCS+-SHA2-128f-simple */

/* Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED] */

// Key generation with seed
int sphincs_sha2_128f_seed_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);

// Standard Key Generation
int sphincs_sha2_128f_keypair(uint8_t *pk, uint8_t *sk);

// Detached Signature Generation
int sphincs_sha2_128f_signature(uint8_t *sig, size_t *siglen,
                                const uint8_t *m, size_t mlen,
                                const uint8_t *sk);

// Combined Signature and Message
int sphincs_sha2_128f_sign_message(uint8_t *sm, size_t *smlen,
                                    const uint8_t *m, size_t mlen,
                                    const uint8_t *sk);

// Detached Signature Verification
int sphincs_sha2_128f_verify(const uint8_t *sig, size_t siglen,
                            const uint8_t *m, size_t mlen,
                            const uint8_t *pk);

// Verify And Extract Message
int sphincs_sha2_128f_open_message(uint8_t *m, size_t *mlen,
                                    const uint8_t *sm, size_t smlen,
                                    const uint8_t *pk);

/* SPHINCS+-SHA2-128s-simple */
int sphincs_sha2_128s_seed_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);

int sphincs_sha2_128s_keypair(uint8_t *pk, uint8_t *sk);

// 서명 부분
int sphincs_sha2_128s_sign_message(uint8_t *sm, size_t *smlen,
                                  const uint8_t *m, size_t mlen,
                                  const uint8_t *sk);
int sphincs_sha2_128s_signature(uint8_t *sig, size_t *siglen,
                               const uint8_t *m, size_t mlen,
                               const uint8_t *sk);
// 검증 부분
int sphincs_sha2_128s_verify(const uint8_t *sig, size_t siglen,
                            const uint8_t *m, size_t mlen,
                            const uint8_t *pk);

int sphincs_sha2_128s_open_message(uint8_t *m, size_t *mlen,
                                  const uint8_t *sm, size_t smlen,
                                  const uint8_t *pk);


/* SPHINCS+-SHA2-192f-simple */
int sphincs_sha2_192f_seed_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);

int sphincs_sha2_192f_keypair(uint8_t *pk, uint8_t *sk);

// 서명 부분 구현
int sphincs_sha2_192f_sign_message(uint8_t *sm, size_t *smlen,
                                    const uint8_t *m, size_t mlen,
                                    const uint8_t *sk);
int sphincs_sha2_192f_signature(uint8_t *sig, size_t *siglen,
                                const uint8_t *m, size_t mlen,
                                const uint8_t *sk);

// 검증 부분 구현
int sphincs_sha2_192f_verify(const uint8_t *sig, size_t siglen,
                                const uint8_t *m, size_t mlen,
                                const uint8_t *pk);
int sphincs_sha2_192f_open_message(uint8_t *m, size_t *mlen,
                                    const uint8_t *sm, size_t smlen,
                                    const uint8_t *pk);

/* SPHINCS+-SHA2-192s-simple */
int sphincs_sha2_192s_seed_keypair(uint8_t *pk, uint8_t *sk, uint8_t *seed);

int sphincs_sha2_192s_keypair(uint8_t *pk, uint8_t *sk);

int sphincs_sha2_192s_sign_message(uint8_t *sm, size_t *smlen,
                                    const uint8_t *m, size_t mlen, 
                                    const uint8_t *sk);

int sphincs_sha2_192s_signature(uint8_t *sig, size_t signlen,
                            const uint8_t *m, size_t mlen,
                            const uint8_t *sk);
// 시그니처만 검증하는 함수
int sphincs_sha2_192s_verify(const uint8_t *sig, size_t siglen,
                                const uint8_t *m, size_t mlen,
                                const uint8_t *pk);

// 시그니처 || 메시지 검증 하는 함수, 최종저으로 메시지만 남게된다. x
int sphincs_sha2_192s_open_message(uint8_t *m, size_t *mlen,
                                        const uint8_t *sm, size_t smlen,
                                        const uint8_t *pk);
    




/* ===================================================  */
#define NTESTS 5
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

/* ===================================================  */
/* SPHINCS+-SHA2-128f-simple */
#define SPHINCS_SHA2_128F_PUBLIC_KEY_BYTES 32
#define SPHINCS_SHA2_128F_SECRET_KEY_BYTES 64
#define SPHINCS_SHA2_128F_SIGNATURE_BYTES 17088

/* SPHINCS+-SHA2-128s-simple */
#define SPHINCS_SHA2_128S_PUBLIC_KEY_BYTES 32
#define SPHINCS_SHA2_128S_SECRET_KEY_BYTES 64
#define SPHINCS_SHA2_128S_SIGNATURE_BYTES 7856

/* SPHINCS+ SHA2-192f-simple */
#define SPHINCS_SHA2_192F_PUBLIC_KEY_BYTES 48
#define SPHINCS_SHA2_192F_SECRET_KEY_BYTES 96
#define SPHINCS_SHA2_192F_SIGNATURE_BYTES 35664

/* SPHINCS+ SHA2-192s-simple */
#define SPHINCS_SHA2_192S_PUBLIC_KEY_BYTES 48
#define SPHINCS_SHA2_192S_SECRET_KEY_BYTES 96
#define SPHINCS_SHA2_192S_SIGNATURE_BYTES 16224


/* ===================================================  */



#endif