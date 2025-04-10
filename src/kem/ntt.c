#include "ntt.h"
#include "reduce.h"
#include <stdint.h>

/* zetas 테이블 - 모든 ML-KEM 보안 레벨에서 동일 (N=256, Q=3329 사용)
   네임스페이스 제거, 전역에서 접근 가능하도록 extern으로 선언 */
const int16_t zetas[128] = {
    -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
    -171,   622,  1577,   182,   962, -1202, -1474,  1468,
    573, -1325,   264,   383,  -829,  1458, -1602,  -130,
    -681,  1017,   732,   608, -1542,   411,  -205, -1571,
    1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
    516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
    -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
    -398,   961, -1508,  -725,   448, -1065,   677, -1275,
    -1103,   430,   555,   843, -1251,   871,  1550,   105,
    422,   587,   177,  -235,  -291,  -460,  1574,  1653,
    -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
    -1590,   644,  -872,   349,   418,   329,  -156,   -75,
    817,  1097,   603,   610,  1322, -1285, -1465,   384,
    -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
    -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
    -108,  -308,   996,   991,   958, -1460,  1522,  1628
};

/*************************************************
* Name:        fqmul
*
* Description: 곱셈 후 Montgomery 리덕션 수행
*
* Arguments:   - int16_t a: 첫 번째 인수
*              - int16_t b: 두 번째 인수
*              - PQC_MODE mode: 동작 모드 (여기서는 사용하지 않음)
*
* Returns 16-bit integer congruent to a*b*R^{-1} mod q
**************************************************/

static int16_t fqmul(int16_t a, int16_t b, PQC_MODE mode) {
    // 모드 매개변수는 인터페이스 일관성을 위해 추가했지만,
    // ML-KEM의 경우 내부적으로는 모든 모드가 동일한 Montgomery 상수를 사용하므로 무시해도 됨
    // reduce.h에 있는 함수 이름을 사용 (예 : montgomery_reduce)
    (void)mode; // 경고 방지
    return montgomery_reduce((int32_t)a * b);
}

/*************************************************
* Name:        mlkem_ntt
*
* Description: 다항식에 대한 NTT(Number-theoretic transform) 변환 수행.
*              입력은 표준 순서, 출력은 비트 역순 순서.
*
* Arguments:   - int16_t r[MLKEM_N]: 입력/출력 다항식 계수 배열 (in-place 변환)
*              - PQC_MODE mode: 동작 모드 (PQC_MODE_1/2/3 - ML-KEM-512/768/1024)
**************************************************/

void mlkem_ntt(int16_t r[MLKEM_N], PQC_MODE mode) {
    unsigned int len, start, j, k;
    int16_t t, zeta_val;

    // 모드 매개변수는 인터페이스 일관성을 위해 추가됐지만,
    // ML-KEM의 경우 내부적으로는 모든 모드가 동일한 NTT 연산을 수행함으로 무시.
    (void)mode; // 경고 방지

    k = 1;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < MLKEM_N; start = j + len) {
            zeta_val = zetas[k++];
            for (j = start; j < start + len; j++) {
                t = fqmul(zeta_val, r[j + len], mode);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
        }
    }
}


/*************************************************
* Name:        mlkem_invntt
*
* Description: 다항식에 대한 역방향 NTT 변환 및 Montgomery 변환 수행.
*              입력은 비트 역순 순서, 출력은 표준 순서.
*
* Arguments:   - int16_t r[MLKEM_N]: 입력/출력 다항식 계수 배열 (in-place 변환)
*              - PQC_MODE mode: 동작 모드 (PQC_MODE_1/2/3 - ML-KEM-512/768/1024)
**************************************************/

void mlkem_invntt(int16_t r[MLKEM_N], PQC_MODE mode) {
    unsigned int start, len, j, k;
    int16_t t, zeta_val;
    const int16_t f = 1441; // mont^2/128

    // 모드 매개변수는 인터페이스 일관성을 위해 추가했지만,
    // ML-KEM 의 경우 내부적으로 모드가 동일한 INTT 연산을 수행함으로 무시.
    (void)mode; // 경고 방지

    k = 127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < MLKEM_N; start = j + len) {
            zeta_val = zetas[k--];
            for (j = start; j < start + len; j++) {
                t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = r[j + len] - t;
                r[j + len] = fqmul(zeta_val, r[j + len], mode);
            }
        }
    }

    for (j = 0; j < MLKEM_N; j++) {
        r[j] = fqmul(r[j], f, mode);
    }
}

/*************************************************
* Name:        mlkem_basemul_2
*
* Description: Zq[X]/(X^2-zeta)에서 다항식 곱셈 수행.
*              NTT 도메인에서 Rq 원소 곱셈에 사용됨.
*
* Arguments:   - int16_t r[2]: 결과 저장할 배열
*              - const int16_t a[2]: 첫 번째 입력 배열
*              - const int16_t b[2]: 두 번째 입력 배열
*              - int16_t zeta: 감소 다항식 정의하는 정수
*              - PQC_MODE mode: 동작 모드 (PQC_MODE_1/2/3 - ML-KEM-512/768/1024)
**************************************************/
void mlkem_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta, PQC_MODE mode) {
    // 모드 매개변수는 인터페이스 일관성을 위해 추가
    // ML-KEM 경우 내부적으로는 모든 모드가 동일한 연산 수행
    r[0] = fqmul(a[1], b[1], mode);
    r[0] = fqmul(r[0], zeta, mode);
    r[0] += fqmul(a[0], b[0], mode);
    r[1] = fqmul(a[0], b[1], mode);
    r[1] += fqmul(a[1], b[0], mode);
}