#include "poly.h"
#include "ntt.h"
#include "reduce.h"
#include "symmetric.h"
#include "verify.h"
#include "cbd.h"
#include "get_func.h"
#include <string.h>


/*************************************************
* Name:        mlkem_poly_compress
*
* Description: 다항식 압축 및 직렬화
*              - ML-KEM-512/768: 4비트 압축
*              - ML-KEM-1024: 5비트 압축
*
* Arguments:   - uint8_t *r: 결과 바이트 배열 포인터
*              - const poly *a: 입력 다항식 포인터
*              - PQC_MODE mode: 동작 모드
**************************************************/

void mlkem_poly_compress(uint8_t *r, const poly *a, PQC_MODE mode) {
    unsigned int i, j;
    int16_t u;
    uint32_t d0;
    uint8_t t[8];

    if (mode == PQC_MODE_1 || mode == PQC_MODE_2) { // ML-KEM-512/768
        for (i = 0; i < MLKEM_N; i++) {
            for (j = 0; j < 8; j++) {
                // 표준 양수 대표값으로 매핑
                u = a->coeffs[8 * i + j];
                u += (u >> 15) & MLKEM_Q;

                // 최적화된 계산 : ((((uint16_t)u << 4) + KYBER_Q/2)/KYBER_Q) & 15
                d0 = u << 4;
                d0 += 1665;
                d0 *= 80635;
                d0 >>= 28;
                t[j] = d0 & 0xf;
            }
            r[0] = t[0] | (t[1] << 4);
            r[1] = t[2] | (t[3] << 4);
            r[2] = t[4] | (t[5] << 4);
            r[3] = t[6] | (t[7] << 4);
            r += 4;
        }
    } 
    else if (mode == PQC_MODE_3) { // ML-KEM-1024 : 5비트 압축
        for (i = 0; i < MLKEM_N; i++) {
            for (j = 0; j < 8; j++) {
                u = a->coeffs[8 * i + j];
                u += (u >> 15) & MLKEM_Q;

                // 최적화된 계산: ((((uint32_t)u << 5) + KYBER_Q/2)/KYBER_Q) & 31
                d0 = u << 5;
                d0 += 1664;
                d0 *= 40318;
                d0 >>= 27;
                t[j] = d0 & 0x1f;
            }

            r[0] = (t[0] >> 0) | (t[1] << 5);
            r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
            r[2] = (t[3] >> 1) | (t[4] << 4);
            r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
            r[4] = (t[6] >> 2) | (t[7] << 3);
            r += 5;
        }
    }
    else {
        // 지원하지 않는 모드
        memset(r, 0, get_mlkem_polyveccompressedbytes(mode));
    }
}

/*************************************************
* Name:        mlkem_poly_decompress
*
* Description: 압축된 다항식 역직렬화 및 압축 해제
*              - ML-KEM-512/768: 4비트 압축 해제
*              - ML-KEM-1024: 5비트 압축 해제
*
* Arguments:   - poly *r: 결과 다항식 포인터
*              - const uint8_t *a: 입력 바이트 배열 포인터
*              - PQC_MODE mode: 동작 모드
**************************************************/
void mlkem_poly_decompress(poly *r, const uint8_t *a, PQC_MODE mode) {
    if (mode == PQC_MODE_1 || mode == PQC_MODE_2) { // ML-KEM-512/768
        size_t i;
        for (i = 0; i < MLKEM_N / 2; i++) {
            r->coeffs[2 * i + 0] = ((uint16_t)(a[0] & 15) * MLKEM_Q + 8) >> 4;
            r->coeffs[2 * i + 1] = ((uint16_t)(a[0] >> 4) * MLKEM_Q + 8) >> 4;
            a += 1;
        }
    }
    else if (mode == PQC_MODE_3) { // MLKEM-1024
        size_t i, j;
        uint8_t t[8];
        for (i = 0; i < MLKEM_N / 8; i++) {
            t[0] = (a[0] >> 0);
            t[1] = (a[0] >> 5) | (a[1] << 3);
            t[2] = (a[1] >> 2);
            t[3] = (a[1] >> 7) | (a[2] << 1);
            t[4] = (a[2] >> 4) | (a[3] << 4);
            t[5] = (a[3] >> 1);
            t[6] = (a[3] >> 6) | (a[4] << 2);
            t[7] = (a[4] >> 3);
            a += 5;

            for (j = 0; j < 8; j++) {
                r->coeffs[8 * i + j] = ((uint32_t)(t[j] & 31) * MLKEM_Q + 16) >> 5;
            }
        }

    }
    else {
        // 지원하지 않는 모드
        memset(r->coeffs, 0, MLKEM_N * sizeof(int16_t));
    }
}


/*************************************************
* Name:        mlkem_poly_tobytes
*
* Description: 다항식 직렬화
*              모든 모드에서 동일한 알고리즘 사용
*
* Arguments:   - uint8_t *r: 결과 바이트 배열 포인터
*              - const poly *a: 입력 다항식 포인터
*              - PQC_MODE mode: 동작 모드
**************************************************/

void mlkem_poly_tobytes(uint8_t *r, const poly *a, PQC_MODE mode) {
    size_t i;
    uint16_t t0, t1;
    (void)mode; // 모드 함수 에러방지

    for (i = 0; i < MLKEM_N / 2; i++) {
        // 표준 양수 대표값으로 매핑
        t0 = a->coeffs[2 * i];
        t0 += ((int16_t)t0 >> 15) & MLKEM_Q;
        t1 = a->coeffs[2 * i + 1];
        t1 += ((int16_t)t1 >> 15) & MLKEM_Q;
        r[3 * i + 0] = (uint8_t)(t0 >> 0);
        r[3 * i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3 * i + 2] = (uint8_t)(t1 >> 4);
    }
}

/*************************************************
* Name:        mlkem_poly_frombytes
*
* Description: 바이트 배열에서 다항식으로 역직렬화
*              모든 모드에서 동일한 알고리즘 사용
*
* Arguments:   - poly *r: 결과 다항식 포인터
*              - const uint8_t *a: 입력 바이트 배열 포인터
*              - PQC_MODE mode: 동작 모드
**************************************************/

void mlkem_poly_frombytes(poly *r, const uint8_t *a, PQC_MODE mode) {
    size_t i;
    (void)mode; // 모드 함수 에러방지

    for (i = 0; i < MLKEM_N / 2; i++) {
        r->coeffs[2 * i] = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
        r->coeffs[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;
    }
}

/*************************************************
* Name:        mlkem_poly_frommsg
*
* Description: 32바이트 메시지를 다항식으로 변환
*              모든 모드에서 동일한 알고리즘 사용
*
* Arguments:   - poly *r: 결과 다항식 포인터
*              - const uint8_t *msg: 입력 메시지 포인터
*              - PQC_MODE mode: 동작 모드
**************************************************/

void mlkem_poly_frommsg(poly *r, const uint8_t * msg, PQC_MODE mode) {
    size_t i, j;
    (void)mode; // 모드 함수 에러방지

    for (i = 0; i < MLKEM_N / 8; i++) {
        for (j = 0; j < 8; j++) {
            r->coeffs[8 * i + j] = 0;
            mlkem_cmov_int16(r->coeffs + 8 * i + j, ((MLKEM_Q + 1) / 2), (msg[i] >> j) & 1);
        }
    }
}

/*************************************************
* Name:        mlkem_poly_tomsg
*
* Description: 다항식을 32바이트 메시지로 변환
*              모든 모드에서 동일한 알고리즘 사용
*
* Arguments:   - uint8_t *msg: 결과 메시지 포인터
*              - const poly *a: 입력 다항식 포인터
*              - PQC_MODE mode: 동작 모드
**************************************************/

void mlkem_poly_tomsg(uint8_t *msg, const poly *a, PQC_MODE mode) {
    unsigned int i, j;
    uint32_t t; 
    (void)mode; // 모드 함수 에러방지

    for (i = 0; i < MLKEM_N / 8; i++) {
        msg[i] = 0;
        for (j = 0; j < 8; j++) {
            t = a->coeffs[8 * i + j];
            // 최적화된 계산: (t <<1) + KYBER_Q/2)/KYBER_Q & 1;
            t <<= 1;
            t += 1665;
            t *= 80635;
            t >>= 28;
            msg[i] |= t << j;
        }
    }
}

/*************************************************
* Name:        mlkem_poly_getnoise_eta1
*
* Description: 결정적 노이즈 다항식 생성 (분포 매개변수 ETA1)
*              - ML-KEM-512: ETA1=3
*              - ML-KEM-768/1024: ETA1=2
*
* Arguments:   - poly *r: 결과 다항식 포인터
*              - const uint8_t *seed: 시드 (MLKEM_SYMBYTES 크기)
*              - uint8_t nonce: 논스 바이트
*              - PQC_MODE mode: 동작 모드
**************************************************/

void mlkem_poly_getnoise_eta1(poly *r, const uint8_t *seed, uint8_t nonce, PQC_MODE mode) {
    // 모드에 따라 eta 1 값을 가져옴 (512 : 3, 768/1024 : 2)
    unsigned int eta1 = get_mlkem_eta1(mode);

    // eta1이 다르면 buf 크기도 다름
    uint8_t buf[eta1 * MLKEM_N / 4];
    // 시드와 논스를 사용하여 랜덤바이트 생성
    prf(buf, sizeof(buf), seed, nonce, mode);

    // 중심화 이항 분포 노이즈 생성
    poly_cbd_eta1(r, buf, mode);

}

/*************************************************
* Name:        mlkem_poly_getnoise_eta2
*
* Description: 결정적 노이즈 다항식 생성 (분포 매개변수 ETA2)
*              모든 모드에서 ETA2=2 사용
*
* Arguments:   - poly *r: 결과 다항식 포인터
*              - const uint8_t *seed: 시드 (MLKEM_SYMBYTES 크기)
*              - uint8_t nonce: 논스 바이트
*              - PQC_MODE mode: 동작 모드
**************************************************/

void mlkem_poly_getnoise_eta2(poly *r, const uint8_t *seed, uint8_t nonce, PQC_MODE mode) {
    unsigned int eta2 = get_mlkem_eta2(mode);   // 모든 모드에서 2
    uint8_t buf[eta2 * MLKEM_N / 4];
    prf(buf, sizeof(buf), seed, nonce, mode);
    poly_cbd_eta2(r, buf, mode);

}

/*************************************************
* Name:        mlkem_poly_ntt
*
* Description: 다항식에 NTT 변환 수행
*              모든 모드에서 동일한 알고리즘 사용
*
* Arguments:   - poly *r: 변환할 다항식 포인터
*              - PQC_MODE mode: 동작 모드
**************************************************/
void mlkem_poly_ntt(poly *r, PQC_MODE mode) {
    mlkem_ntt(r->coeffs, mode);
    mlkem_poly_reduce(r, mode);
}

/*************************************************
* Name:        mlkem_poly_invntt_tomont
*
* Description: 다항식에 역 NTT 변환 수행
*              모든 모드에서 동일한 알고리즘 사용
*
* Arguments:   - poly *r: 변환할 다항식 포인터
*              - PQC_MODE mode: 동작 모드
**************************************************/
void mlkem_poly_invntt_tomont(poly *r, PQC_MODE mode) {
    mlkem_invntt(r->coeffs, mode);
}


/*************************************************
* Name:        mlkem_poly_basemul_montgomery
*
* Description: NTT 도메인에서 두 다항식 곱셈
*              모든 모드에서 동일한 알고리즘 사용
*
* Arguments:   - poly *r: 결과 다항식 포인터
*              - const poly *a: 첫 번째 입력 다항식 포인터
*              - const poly *b: 두 번째 입력 다항식 포인터
*              - PQC_MODE mode: 동작 모드
**************************************************/
void mlkem_poly_basemul_montgomery(poly *r, const poly *a, const poly *b, PQC_MODE mode) {
    size_t i;
    
    for (i = 0; i < MLKEM_N / 4; i++) {
        // 계수별 곱셈 (4개씩 묶어서 처리)
        mlkem_basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], zetas[64 + i], mode);
        mlkem_basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2], &b->coeffs[4 * i + 2], -zetas[64 + i], mode);
    }
}

/*************************************************
* Name:        mlkem_poly_tomont
*
* Description: 다항식의 모든 계수를 Montgomery 도메인으로 변환
*              모든 모드에서 동일한 알고리즘 사용
*
* Arguments:   - poly *r: 변환할 다항식 포인터
*              - PQC_MODE mode: 동작 모드
**************************************************/
void mlkem_poly_tomont(poly *r, PQC_MODE mode) {
    size_t i;
    const int16_t f = (1ULL << 32) % MLKEM_Q;
    (void)mode; // 모드 독립적 함수

    for (i = 0; i < MLKEM_N; i++) {
        r->coeffs[i] = mlkem_montgomery_reduce((int32_t)r->coeffs[i] * f);
    }
}



/*************************************************
* Name:        mlkem_poly_reduce
*
* Description: 다항식의 모든 계수에 Barrett 리덕션 적용
*              모든 모드에서 동일한 알고리즘 사용
*
* Arguments:   - poly *r: 리덕션 적용할 다항식 포인터
*              - PQC_MODE mode: 동작 모드
**************************************************/
void mlkem_poly_reduce(poly *r, PQC_MODE mode) {
    size_t i;
    (void)mode; // 모드 독립적 함수

    for (i = 0; i < MLKEM_N; i++) {
        r->coeffs[i] = mlkem_barrett_reduce(r->coeffs[i]);
    }
}


/*************************************************
* Name:        mlkem_poly_add
*
* Description: 두 다항식 더하기 (r = a + b)
*              모든 모드에서 동일한 알고리즘 사용
*
* Arguments:   - poly *r: 결과 다항식 포인터
*              - const poly *a: 첫 번째 입력 다항식 포인터
*              - const poly *b: 두 번째 입력 다항식 포인터
*              - PQC_MODE mode: 동작 모드
**************************************************/
void mlkem_poly_add(poly *r, const poly *a, const poly *b, PQC_MODE mode) {
    size_t i;
    (void)mode; // 모드 독립적 함수

    for (i = 0; i < MLKEM_N; i++) {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}


/*************************************************
* Name:        mlkem_poly_sub
*
* Description: 두 다항식 빼기 (r = a - b)
*              모든 모드에서 동일한 알고리즘 사용
*
* Arguments:   - poly *r: 결과 다항식 포인터
*              - const poly *a: 첫 번째 입력 다항식 포인터
*              - const poly *b: 두 번째 입력 다항식 포인터
*              - PQC_MODE mode: 동작 모드
**************************************************/
void mlkem_poly_sub(poly *r, const poly *a, const poly *b, PQC_MODE mode) {
    size_t i;
    (void)mode; // 모드 독립적 함수

    for (i = 0; i < MLKEM_N; i++) {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}