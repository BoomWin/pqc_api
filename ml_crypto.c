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

/* ML-KEM-1024 implementation */
int ml_kem_1024_keypair_gen(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
}

int ml_kem_1024_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct, ss, pk);
}

int ml_kem_1024_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* ML-DSA-44 implementations */
int ml_dsa_44_keypair_gen(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
}
// 서명만
int ml_dsa_44_sign(uint8_t *sig, size_t *sig_len,
                   const uint8_t *msg, size_t msg_len,
                   const uint8_t *sk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, sig_len, msg, msg_len, sk);
}
// 서명이랑 메시지 같이
int ml_dsa_44_sign_message(uint8_t *sm, size_t *smlen,
                           const uint8_t *m, size_t mlen,
                           const uint8_t *sk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign(sm, smlen, m, mlen, sk);
}
// 서명만 검증
int ml_dsa_44_verify(const uint8_t *sig, size_t sig_len,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *pk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, sig_len, msg, msg_len, pk);
}

// 서명이랑 메시지 같이 검증
int ml_dsa_44_open_message(uint8_t *m, size_t *mlen,
                           const uint8_t *sm, size_t smlen,
                           const uint8_t *sk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_open(m, mlen, sm, smlen, sk);
}

/* ML-DSA-65 implementations */
int ml_dsa_65_keypair_gen(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
}

int ml_dsa_65_sign(uint8_t *sig, size_t *sig_len,
                   const uint8_t *msg, size_t msg_len,
                   const uint8_t *sk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, sig_len, msg, msg_len, sk);
}

int ml_dsa_65_sign_message(uint8_t *sm, size_t *smlen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign(sm, smlen, m, mlen, sk);
}


int ml_dsa_65_verify(const uint8_t *sig, size_t sig_len,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *pk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, sig_len, msg, msg_len, pk);
}

int ml_dsa_65_open_message(uint8_t *m, size_t *mlen,
                          const uint8_t *sm, size_t smlen,
                          const uint8_t *pk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
}

/* ML-DSA-87 implementations */
int ml_dsa_87_keypair_gen(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk, sk);
}

int ml_dsa_87_sign(uint8_t *sig, size_t *sig_len,
                   const uint8_t *msg, size_t msg_len,
                   const uint8_t *sk) {
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(sig, sig_len, msg, msg_len, sk);
}

int ml_dsa_87_sign_message(uint8_t *sm, size_t *smlen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk) {
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign(sm, smlen, m, mlen, sk);
}

int ml_dsa_87_verify(const uint8_t *sig, size_t sig_len,
                     const uint8_t *msg, size_t msg_len,
                     const uint8_t *pk) {
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(sig, sig_len, msg, msg_len, pk);
}

int ml_dsa_87_open_message(uint8_t *m, size_t *mlen,
                          const uint8_t *sm, size_t smlen,
                          const uint8_t *pk) {
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_open(m, mlen, sm, smlen, pk);
}