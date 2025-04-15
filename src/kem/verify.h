#ifndef VERIFY_H
#define VERIFY_H

#include "../../include/pqc_params.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief 두 바이트 배열을 비교하여 동일 여부를 확인
 * @param a 첫 번째 바이트 배열
 * @param b 두 번째 바이트 배열
 * @param len 비교할 바이트 수
 * @return 두 배열이 동일하면 0, 다르면 -1
 */
int mlkem_verify(const uint8_t *a, const uint8_t *b, size_t len);

/**
 * @brief 조건부로 바이트 배열을 복사
 * @param r 결과를 저장할 바이트 배열
 * @param x 복사할 소스 바이트 배열
 * @param len 복사할 바이트 수
 * @param b 조건 플래그 (0이면 복사하지 않음, 1이면 복사)
 */

void mlkem_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b);


/**
 * @brief 조건부로 16비트 정수를 복사
 * @param r 결과를 저장할 16비트 정수 포인터
 * @param v 복사할 16비트 정수 값
 * @param b 조건 플래그 (0이면 복사하지 않음, 1이면 복사)
 */

void mlkem_cmov_int16(int16_t *r, int16_t v, uint16_t b);

#endif /* VERIFY_H */