#ifndef REDUCE_H
#define REDUCE_H

#include "../include/pqc_params.h"
#include <stdint.h>

/**
 * Montgomery 리덕션 상수
 */
#define MLKEM_MONT (-1044) // 2^16 mod q

/**
 * 모듈러 역수 상수
 */
#define MLKEM_QINV (-3327) // q^-1 mod 2^16

/**
 * @brief Montgomery 리덕션 수행
 * @param a 리덕션할 32비트 정수
 * @param mode 동작 모드 (PQC_MODE_1/2/3 - ML-KEM-512/768/1024)
 * @return 리덕션된 16비트 정수
 */
int16_t mlkem_montgomery_reduce(int32_t a);

/**
 * @brief Barrett 리덕션 수행
 * @param a 리덕션할 16비트 정수
 * @param mode 동작 모드 (PQC_MODE_1/2/3 - ML-KEM-512/768/1024)
 * @return 리덕션된 16비트 정수
 */
int16_t mlkem_barrett_reduce(int16_t a);

#endif