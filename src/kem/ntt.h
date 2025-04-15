#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "../../include/pqc_params.h" // 통합된 파라미터 헤더

// NTT 계산에 사용되는 zetas 테이블 선언
// 참고: 내부에서는 모든 ML-KEM 레벨에서 동일한 zetas 테이블을 사용하지만
// 일관성을 위해 외부에 노출하고, 필요시 mode에 따라 선택할 수 있게 합니다.
extern const int16_t zetas[128];

/**
 * @brief 다항식 순방향 NTT 변환. 입력을 직접 수정합니다 (in-place).
 * @param r 변환할 다항식 계수 배열 (크기 MLKEM_N).
 *          표준 순서 입력 -> 비트 역순 NTT 도메인 출력.
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_ntt(int16_t r[MLKEM_N], int mode);

/**
 * @brief 다항식 역방향 NTT 변환. 입력을 직접 수정합니다 (in-place).
 * @param r 변환할 다항식 계수 배열 (크기 MLKEM_N).
 *          비트 역순 NTT 도메인 입력 -> 표준 순서 출력.
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_invntt(int16_t r[MLKEM_N], int mode);

/**
 * @brief 두 계수에 대한 기본 곱셈 연산 (NTT 도메인에서 사용).
 * @param r 결과를 저장할 배열 (크기 2)
 * @param a 첫 번째 입력 배열 (크기 2)
 * @param b 두 번째 입력 배열 (크기 2)
 * @param zeta 트위들 인수 (twiddle factor)
 * @param mode 동작 모드 (int_1/2/3 - ML-KEM-512/768/1024)
 */
void mlkem_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta, int mode);

#endif