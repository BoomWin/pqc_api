// poly.h
#ifndef POLY_H
#define POLY_H

#include "../../include/pqc_params.h"
#include <stdint.h>

/*
 * 다항식 R_q = Z_q[X]/(X^n + 1)의 원소.
 * 표현: coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */

typedef struct {
    int16_t coeffs[MLKEM_N]; // KYBER_N 대신 통합 상수 MLKEM_N 사용
} poly;

/**
 * @brief 다항식을 압축된 바이트 형태로 변환
 * @param r 압축된 결과 저장 배열 (크기는 모드에 따라 다름)
 * @param a 압축할 다항식
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_poly_compress(uint8_t *r, const poly *a, int mode);

/**
 * @brief 압축된 바이트 형태를 다항식으로 복원
 * @param r 복원된 결과 다항식
 * @param a 압축된 바이트 배열
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_poly_decompress(poly *r, const uint8_t *a, int mode);

/**
 * @brief 다항식을 직렬화된 바이트 배열로 변환
 * @param r 직렬화된 바이트 배열 (크기 MLKEM_POLYBYTES)
 * @param a 변환할 다항식
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_poly_tobytes(uint8_t *r, const poly *a, int mode);

/**
 * @brief 직렬화된 바이트 배열을 다항식으로 변환
 * @param r 결과 다항식
 * @param a 직렬화된 바이트 배열
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_poly_frombytes(poly *r, const uint8_t *a, int mode);


/**
 * @brief 메시지를 다항식으로 변환
 * @param r 결과 다항식
 * @param msg 메시지 바이트 배열
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_poly_frommsg(poly *r, const uint8_t *msg, int mode);


/**
 * @brief 다항식을 메시지로 변환
 * @param msg 결과 메시지 바이트 배열
 * @param a 변환할 다항식
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_poly_tomsg(uint8_t *msg, const poly *a, int mode);


/**
 * @brief 노이즈 다항식 생성 (ETA1 분포)
 * @param r 결과 노이즈 다항식
 * @param seed 시드 바이트 배열
 * @param nonce 논스 값
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_poly_getnoise_eta1(poly *r, const uint8_t *seed, uint8_t nonce, int mode);

/**
 * @brief 노이즈 다항식 생성 (ETA2 분포)
 * @param r 결과 노이즈 다항식
 * @param seed 시드 바이트 배열
 * @param nonce 논스 값
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_poly_getnoise_eta2(poly *r, const uint8_t *seed, uint8_t nonce, int mode);


/**
 * @brief 다항식에 NTT 변환 적용
 * @param r 변환할 다항식 (입출력)
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_poly_ntt(poly *r, int mode);


/**
 * @brief 다항식에 역 NTT 변환 및 Montgomery 변환 적용
 * @param r 변환할 다항식 (입출력)
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_poly_invntt_tomont(poly *r, int mode);


/**
 * @brief NTT 도메인 상에서 두 다항식 곱셈 (Montgomery 곱셈)
 * @param r 결과 다항식
 * @param a 첫 번째 입력 다항식 (NTT 도메인)
 * @param b 두 번째 입력 다항식 (NTT 도메인)
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_poly_basemul_montgomery(poly *r, const poly *a, const poly *b, int mode);


/**
 * @brief 다항식을 Montgomery 도메인으로 변환
 * @param r 변환할 다항식 (입출력)
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_poly_tomont(poly *r, int mode);


/**
 * @brief 다항식의 모든 계수에 모듈러 리덕션 적용
 * @param r 리덕션 적용할 다항식 (입출력)
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_poly_reduce(poly *r, int mode);


/**
 * @brief 두 다항식 더하기 (r = a + b)
 * @param r 결과 다항식
 * @param a 첫 번째 입력 다항식
 * @param b 두 번째 입력 다항식
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_poly_add(poly *r, const poly *a, const poly *b, int mode);


/**
 * @brief 두 다항식 빼기 (r = a - b)
 * @param r 결과 다항식
 * @param a 첫 번째 입력 다항식
 * @param b 두 번째 입력 다항식
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_poly_sub(poly *r, const poly *a, const poly *b, int mode);

#endif // POLY_H