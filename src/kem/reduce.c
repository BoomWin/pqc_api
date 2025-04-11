#include "reduce.h"

/*************************************************
* Name:        mlkem_montgomery_reduce
*
* Description: Montgomery 환원; 32비트 정수 a가 주어지면, 
*              a * R^-1 mod q와 합동인 16비트 정수를 계산, 여기서 R=2^16
*
* Arguments:   - int32_t a: 환원할 입력 정수;
*                           {-q2^15,...,q2^15-1} 범위 내에 있어야 함
*
* Returns:     {-q+1,...,q-1} 범위 내에서 a * R^-1 mod q와 합동인 정수
**************************************************/

int16_t mlkem_montgomery_reduce(int32_t a) {
    int16_t t;

    t = (int16_t)a * MLKEM_QINV;
    t = (a- (int32_t)t * MLKEM_Q) >> 16;
    return t;
}

/*************************************************
* Name:        mlkem_barrett_reduce
*
* Description: Barrett 환원; 16비트 정수 a가 주어지면,
*              {-(q-1)/2,...,(q-1)/2} 범위에서 a mod q에 해당하는 중심 대표값 계산
*
* Arguments:   - int16_t a: 환원할 입력 정수
*
* Returns:     {-(q-1)/2,...,(q-1)/2} 범위에서 a mod q와 합동인 정수
**************************************************/

int16_t mlkem_barrett_reduce(int16_t a) {
    int16_t t;
    const uint16_t v = ((1 << 26) + MLKEM_Q / 2) / MLKEM_Q;

    t = ((int32_t)v * a + (1 << 25)) >> 26;
    t *= MLKEM_Q;
    return a - t;
}