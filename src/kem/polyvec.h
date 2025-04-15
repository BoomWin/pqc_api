#ifndef POLYVEC_H
#define POLYVEC_H

#include "poly.h"
#include "../../include/pqc_params.h"
#include "get_func.h"
#include <stdint.h>

typedef struct {
    poly vec[4];
} polyvec;

/**
 * @brief 다항식 벡터 압축 및 직렬화
 * @param r 결과 바이트 배열 포인터
 * @param a 입력 다항식 벡터 포인터
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_polyvec_compress(uint8_t *r, const polyvec *a, int mode);

/**
 * @brief 압축된 다항식 벡터의 역직렬화 및 압축 해제
 * @param r 결과 다항식 벡터 포인터
 * @param a 입력 바이트 배열 포인터
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_polyvec_decompress(polyvec *r, const uint8_t *a, int mode);

/**
 * @brief 다항식 벡터 직렬화
 * @param r 결과 바이트 배열 포인터
 * @param a 입력 다항식 벡터 포인터
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_polyvec_tobytes(uint8_t *r, const polyvec *a, int mode);

/**
 * @brief 바이트 배열에서 다항식 벡터로 역직렬화
 * @param r 결과 다항식 벡터 포인터
 * @param a 입력 바이트 배열 포인터
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_polyvec_frombytes(polyvec *r, const uint8_t *a, int mode);

/**
 * @brief 다항식 벡터의 각 다항식에 NTT 변환 적용
 * @param r 변환할 다항식 벡터 포인터
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_polyvec_ntt(polyvec *r, int mode);

/**
 * @brief 다항식 벡터의 각 다항식에 역 NTT 변환 적용
 * @param r 변환할 다항식 벡터 포인터
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_polyvec_invntt_tomont(polyvec *r, int mode);

/**
 * @brief NTT 도메인에서 두 다항식 벡터의 내적(점곱) 계산
 * @param r 결과 다항식 포인터
 * @param a 첫 번째 입력 다항식 벡터 포인터
 * @param b 두 번째 입력 다항식 벡터 포인터
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b, int mode);

/**
 * @brief 다항식 벡터의 모든 계수에 리덕션 적용
 * @param r 리덕션을 적용할 다항식 벡터 포인터
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_polyvec_reduce(polyvec *r, int mode);

/**
 * @brief 두 다항식 벡터 더하기 (r = a + b)
 * @param r 결과 다항식 벡터 포인터
 * @param a 첫 번째 입력 다항식 벡터 포인터
 * @param b 두 번째 입력 다항식 벡터 포인터
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_polyvec_add(polyvec *r, const polyvec *a, const polyvec *b, int mode);

#endif /* POLYVEC_H */