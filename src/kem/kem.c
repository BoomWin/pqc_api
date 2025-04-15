#include "indcpa.h"
#include "kem.h"
#include "../common/randombytes.h"
#include "symmetric.h"
#include "verify.h"
#include <stddef.h>
#include <string.h>
#include <stdio.h> // 오류 로깅을 위함


int crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins, int mode) {
    size_t indcpa_secretkeybytes, publickeybytes, secretkeybytes;

    indcpa_secretkeybytes = get_mlkem_secretkeybytes(mode);
    publickeybytes = get_mlkem_publickeybytes(mode);
    secretkeybytes = get_mlkem_secretkeybytes(mode); // 전체 비밀키 크기

    // 파라미터 검색 성공 여부 확인
    if (indcpa_secretkeybytes == 0 || publickeybytes == 0 || secretkeybytes == 0) {
        fprintf(stderr, "오류: 모드 %d에 대한 키 크기를 가져오지 못했습니다.\n", mode);
        return -1; // 오류 표시
    }


    // IND-CPA 키 쌍 생성
    indcpa_keypair_derand(pk, sk, coins, mode);

    // 비밀키에 공개키 추가 (sk = indcpa_sk || pk)
    memcpy(sk + indcpa_secretkeybytes, pk, publickeybytes);

    // 비밀키에 공개키 해시 추가 (sk = indcpa_sk || pk || H(pk))
    // hash_h 출력 크기가 MLKEM_SYMBYTES라고 가정
    hash_h(sk + secretkeybytes - 2 * MLKEM_SYMBYTES, pk, publickeybytes);

    // Fujisaki-Okamoto 변환을 위한 z 값 추가 (sk = indcpa_sk || pk || H(pk) || z)
    // coins = (d || z), d는 키 생성용, z는 FO 변환용
    // coins 크기가 2 * MLKEM_SYMBYTES라고 가정
    memcpy(sk + secretkeybytes - MLKEM_SYMBYTES, coins + MLKEM_SYMBYTES, MLKEM_SYMBYTES);
    return 0; // 성공
}

int crypto_kem_keypair(uint8_t *pk, uint8_t *sk, int mode) {
    uint8_t coins[2 * MLKEM_SYMBYTES];
    randombytes(coins, 2 * MLKEM_SYMBYTES);
    // 결정적 버전 호출 및 상태 반환
    // crypto_kem_keypair_derand 함수 호출 시 정상적으로 동작하지 않으면 return 0을 보내니깐.
    return crypto_kem_keypair_derand(pk, sk, coins, mode);
}

// KEM 캡슐화 (FIPS 203 Alg 11 기반 결정적 버전)
// 입력: 공개키 `pk`, 무작위성 `coins` (명세서의 델타, 크기 MLKEM_SYMBYTES)
// 출력: 암호문 `ct`, 공유 비밀 `ss`
int crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss,
                            const uint8_t *pk, const uint8_t *coins, int mode) {
    size_t publickeybytes = get_mlkem_publickeybytes(mode);
    // 파라미터 검증
    if (publickeybytes == 0) {
        fprintf(stderr, "오류: 모드 %d에 대한 공개키 크기를 가져오지 못했습니다.\n", mode);
        return -1;
    }

    uint8_t buf[2 * MLKEM_SYMBYTES];
    /* Will contain key, coins */
    uint8_t kr[2 * MLKEM_SYMBYTES];

    memcpy(buf, coins, MLKEM_SYMBYTES);

    

    /* Multitarget countermeasure for coins + contributory KEM */
    hash_h(buf + MLKEM_SYMBYTES, pk, publickeybytes);
    hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

    /* coins are in kr+KYBER_SYMBYTES*/
    indcpa_enc(ct, buf, pk, kr + MLKEM_SYMBYTES, mode);

    memcpy(ss, kr, MLKEM_SYMBYTES);

    return 0;
}

// KEM 캡슐화 (FIPS 203 Alg 9 기반 표준 버전)
// 내부적으로 무작위성을 생성하고 결정적 버전을 호출합니다.
// 입력: 공개키 `pk`
// 출력: 암호문 `ct`, 공유 비밀 `ss`
int crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk, int mode) {
    uint8_t coins[MLKEM_SYMBYTES]; // FIPS 203 Alg 11 표기법의 'delta'
    // 메시지/델타에 대한 랜덤 바이트 생성
    randombytes(coins, MLKEM_SYMBYTES);
    // 결정적 캡슐화 함수 호출
    // reutrn 0이 성공을 나타내는데, crypt_kem_enc_derand에서 retrun0을 뱉기때문에 0으로 처리
    return crypto_kem_enc_derand(ct, ss, pk, coins, mode);
}

// KEM 복호화
// 입력: 암호문 `ct`, 비밀키 `sk`
// 출력: 공유 비밀 `ss`
int crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, int mode) {
    // mode 값 보호 - 지역 상수에 복사
    const int safe_mode = mode;
    
    printf("안전하게 저장된 mode 값: %d\n", safe_mode);
    
    // 파라미터 가져오기 (safe_mode 사용)
    size_t ciphertextbytes = get_mlkem_ciphertextbytes(safe_mode);
    size_t indcpa_secretkeybytes = get_mlkem_indcpa_secretkeybytes(safe_mode);
    size_t secretkeybytes = get_mlkem_secretkeybytes(safe_mode);

    // 파라미터 검증
    if (ciphertextbytes == 0 || indcpa_secretkeybytes == 0 || secretkeybytes == 0) {
        fprintf(stderr, "오류: 모드 %d에 대한 암호문 크기를 가져오지 못했습니다.\n", safe_mode);
        return -1;
    }

    // 이하 모든 mode 변수 대신 safe_mode 사용
    int fail;
    uint8_t buf[2 * MLKEM_SYMBYTES];
    uint8_t kr[2 * MLKEM_SYMBYTES];
    
    // 정적 크기로 변경 또는 동적 할당으로 변경
    uint8_t cmp[MLKEM_MAX_CIPHERTEXTBYTES + MLKEM_SYMBYTES]; // 최대 크기로 할당
    
    const uint8_t *pk = sk + indcpa_secretkeybytes;

    indcpa_dec(buf, ct, sk, safe_mode); // safe_mode 전달

    memcpy(buf + MLKEM_SYMBYTES, sk + secretkeybytes - 2 * MLKEM_SYMBYTES, MLKEM_SYMBYTES);
    hash_g(kr, buf, 2 * MLKEM_SYMBYTES);

    indcpa_enc(cmp, buf, pk, kr + MLKEM_SYMBYTES, safe_mode); // safe_mode 전달

    fail = mlkem_verify(ct, cmp, ciphertextbytes);

    rkprf(ss, sk + secretkeybytes - MLKEM_SYMBYTES, ct, safe_mode); // safe_mode 전달

    mlkem_cmov(ss, kr, MLKEM_SYMBYTES, (uint8_t) (1 - fail));

    return 0;
}