#include "symmetric.h"
#include "./include/pqc_params.h"

/*************************************************
* Name:        mlkem_shake128_absorb
*
* Description: Kyber 컨텍스트에 특화된 SHAKE128의 흡수 단계
*
* Arguments:   - xof_state *state: (초기화되지 않은) 출력 Keccak 상태에 대한 포인터
*              - const uint8_t *seed: 상태에 흡수될 KYBER_SYMBYTES 크기의 입력에 대한 포인터
*              - uint8_t x: 추가 입력 바이트
*              - uint8_t y: 추가 입력 바이트
*              - PQC_MODE mode: 동작 모드 (PQC_MODE_1/2/3 - ML-KEM-512/768/1024)
**************************************************/

void mlkem_shake128_absorb(xof_state *state,
                            const uint8_t seed[MLKEM_SYMBYTES],
                            uint8_t x,
                            uint8_t y,
                            PQC_MODE mode) {
    uint8_t extseed[MLKEM_SYMBYTES + 2];

    memcpy(extseed, seed, MLKEM_SYMBYTES);
    extseed[MLKEM_SYMBYTES + 0] = x;
    extseed[MLKEM_SYMBYTES + 1] = y;

    shake128_absorb(state, extseed, sizeof(extseed));
}

/*************************************************
* Name:        mlkem_shake256_prf
*
* Description: SHAKE256을 PRF로 사용, 비밀과 공개 입력을 연결한 후
*              outlen 바이트의 SHAKE256 출력을 생성
*
* Arguments:   - uint8_t *out: 출력에 대한 포인터
*              - size_t outlen: 요청된 출력 바이트 수
*              - const uint8_t *key: 키에 대한 포인터 (MLKEM_SYMBYTES 길이)
*              - uint8_t nonce: 단일 바이트 nonce (공개 PRF 입력)
*              - PQC_MODE mode: 동작 모드 (PQC_MODE_1/2/3 - ML-KEM-512/768/1024)
**************************************************/

void mlkem_shake256_prf(uint8_t *out,
                        size_t outlen,
                        const uint8_t key[MLKEM_SYMBYTES],
                        uint8_t nonce,
                        PQC_MODE mode) {
    uint8_t extkey[MLKEM_SYMBYTES + 1];

    memcpy(extkey, key, MLKEM_SYMBYTES);
    extkey[MLKEM_SYMBYTES] = nonce;

    shake256(out, outlen, extkey, sizeof(extkey));
    
}

/*************************************************
* Name:        mlkem_shake256_rkprf
*
* Description: SHAKE256을 재키 가능 PRF로 사용, 비밀과 공개 입력을 연결한 후
*              MLKEM_SSBYTES 바이트의 SHAKE256 출력을 생성
*
* Arguments:   - uint8_t *out: 출력에 대한 포인터 (MLKEM_SSBYTES 크기)
*              - const uint8_t *key: 키에 대한 포인터 (MLKEM_SYMBYTES 길이)
*              - const uint8_t *input: 입력에 대한 포인터 (MLKEM_CIPHERTEXTBYTES 크기)
*              - PQC_MODE mode: 동작 모드 (PQC_MODE_1/2/3 - ML-KEM-512/768/1024)
**************************************************/
void mlkem_shake256_rkprf(uint8_t *out,
                          const uint8_t key[MLKEM_SYMBYTES],
                          const uint8_t *input,
                          PQC_MODE mode) {
    shake256incctx s;
    size_t ciphertext_bytes = get_mlkem_ciphertextbytes(mode);

    shake256_inc_init(&s);
    shake256_inc_absorb(&s, key, MLKEM_SYMBYTES);
    shake256_inc_absorb(&s, input, ciphertext_bytes);
    shake256_inc_finalize(&s);
    shake256_inc_squeeze(out, MLKEM_SSBYTES, &s);
    shake256_inc_ctx_release(&s);
}