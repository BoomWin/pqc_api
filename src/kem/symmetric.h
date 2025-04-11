#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include "fips202.h"
#include "./include/pqc_params.h"
#include <stddef.h>
#include <stdint.h>


/**
 * XOF(확장 출력 함수) 상태 타입
 */
typedef shake128ctx xof_state;

/**
 * @brief SHAKE-128 흡수 함수
 * @param s XOF 상태 구조체
 * @param seed 시드 값 (MLKEM_SYMBYTES 크기)
 * @param x 첫 번째 입력 바이트
 * @param y 두 번째 입력 바이트
 * @param mode 동작 모드 (PQC_MODE_1/2/3 - ML-KEM-512/768/1024)
 */

void mlkem_shake128_absorb(xof_state *s,
                            const uint8_t seed[MLKEM_SYMBYTES],
                            uint8_t x,
                            uint8_t y,
                            PQC_MODE mode);

                         
/**
 * @brief SHAKE-256 기반 PRF(의사 난수 함수) 구현
 * @param out 출력 버퍼
 * @param outlen 출력 버퍼 길이
 * @param key 키 값 (MLKEM_SYMBYTES 크기)
 * @param nonce 일회용 값
 * @param mode 동작 모드 (PQC_MODE_1/2/3 - ML-KEM-512/768/1024)
 */

void mlkem_shake256_prf(uint8_t *out,
                        size_t outlen,
                        const uint8_t key[MLKEM_SYMBYTES],
                        uint8_t nonce,
                        PQC_MODE mode);


 /**
 * @brief SHAKE-256 기반 재키 가능 PRF 구현
 * @param out 출력 버퍼 (모드에 따른 MLKEM_SSBYTES 크기)
 * @param key 키 값 (MLKEM_SYMBYTES 크기)
 * @param input 입력 값 (모드에 따른 MLKEM_CIPHERTEXTBYTES 크기)
 * @param mode 동작 모드 (PQC_MODE_1/2/3 - ML-KEM-512/768/1024)
 */           

void mlkem_shake256_rkprf(uint8_t *out,
                        const uint8_t key[MLKEM_SYMBYTES],
                        const uint8_t *input,
                        PQC_MODE mode);
                        

/**
 * XOF 블록 크기 정의
 */
#define XOF_BLOCKBYTES SHAKE128_RATE


/**
 * 해시, XOF 및 PRF 매크로 함수 정의
 */
#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y, MODE) mlkem_shake128_absorb(STATE, SEED, X, Y, MODE)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define xof_ctx_release(STATE) shake128_ctx_release(STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE, MODE) mlkem_shake256_prf(OUT, OUTBYTES, KEY, NONCE, MODE)
#define rkprf(OUT, KEY, INPUT, MODE) mlkem_shake256_rkprf(OUT, KEY, INPUT, MODE)




#endif /* SYMMETRIC_H */
