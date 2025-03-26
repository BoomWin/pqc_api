#ifndef PQC_SIGN_H
#define PQC_SIGN_H

#include "pqc_params.h"
#include <stdint.h>
#include <stddef.h>

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
int sphincs_sha2_192s_seed_keypair(uint8_t *pk, uint8_t *sk, const uint8_t *seed);

int sphincs_sha2_192s_keypair(uint8_t *pk, uint8_t *sk);

int sphincs_sha2_192s_sign_message(uint8_t *sm, size_t *smlen,
                                    const uint8_t *m, size_t mlen, 
                                    const uint8_t *sk);

int sphincs_sha2_192s_signature(uint8_t *sig, size_t *signlen,
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

#endif 