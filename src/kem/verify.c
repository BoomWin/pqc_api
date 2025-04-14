#include "../common/compat.h"
#include "verify.h"

/*************************************************
* Name:        mlkem_verify
*
* Description: 두 바이트 배열을 상수 시간에 비교
*
* Arguments:   const uint8_t *a: 첫 번째 바이트 배열 포인터
*              const uint8_t *b: 두 번째 바이트 배열 포인터
*              size_t len:       바이트 배열의 길이
*
* Returns:     바이트 배열이 동일하면 0, 다르면 -1
**************************************************/

int mlkem_verify(const uint8_t *a, const uint8_t *b, size_t len) {
    size_t i;
    uint8_t r = 0;

    for (i = 0; i < len; i++) {
        r |= a[i] ^ b[i];
    }
    return (-(uint64_t)r) >> 63;
}

/*************************************************
* Name:        mlkem_cmov
*
* Description: b가 1이면 x에서 r로 len 바이트를 복사하고,
*              b가 0이면 x를 수정하지 않음.
*              b는 {0,1} 중 하나여야 함.
*              음수 정수의 2의 보수 표현을 가정.
*              상수 시간에 실행됨.
*
* Arguments:   uint8_t *r:       출력 바이트 배열 포인터
*              const uint8_t *x: 입력 바이트 배열 포인터
*              size_t len:       복사할 바이트 수
*              uint8_t b:        조건 비트; {0,1} 중 하나여야 함
**************************************************/
void mlkem_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b) {
    size_t i;

    PQCLEAN_PREVENT_BRANCH_HACK(b);

    b = -b;
    for (i = 0; i < len; i++) {
        r[i] ^= b & (r[i] ^ x[i]);
    }
}