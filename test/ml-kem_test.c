#include <stdio.h>
#include <string.h>
#include "../src/kem/kem.h"
#include "../src/kem/poly.h"
#include "../src/kem/polyvec.h"
#include "../src/kem/symmetric.h"
#include "../src/kem/verify.h"
#include "../include/pqc_params.h"
#include "../src/kem/get_func.h"
#include "../src/kem/mode_config.h"

#define NTESTS 5

static void printbytes(const uint8_t *x, size_t xlen) {
    size_t i;
    for (i = 0; i < xlen; i++) {
        printf("%02x", x[i]);
    }
    printf("\n");
}

void test_kem_mode(int mode) {
    // 전역 변수 설정 (한 번만)
    mlkem_set_mode(mode);
    
    uint8_t key_a[MLKEM_SSBYTES], key_b[MLKEM_SSBYTES];
    uint8_t pk[MLKEM_PUBLICKEYBYTES];
    uint8_t ct[MLKEM_CIPHERTEXTBYTES];
    uint8_t sk[MLKEM_SECRETKEYBYTES];

    int i, j;
    printf(" KEM 버전에서 PQC_MODE 1은 ML-KEM-512\n");
    printf(" KEM 버전에서 PQC_MODE 2는 ML-KEM-768\n");
    printf(" KEM 버전에서 PQC_MODE 3은 ML-KEM-1024\n");
    printf("\n ==== Testing Mode %d === \n", mode);

    for (i = 0; i < NTESTS; i++) {
        printf("\n TEST %d:\n", i + 1);

        // 키 쌍 생성 (mode 매개변수 전달 없음)
        crypto_kem_keypair(pk, sk);
        printf(" 키 생성 성공 !\n");
        printf("Public Key : ");
        printbytes(pk, MLKEM_PUBLICKEYBYTES);
        printf("Secret Key : ");
        printbytes(sk, MLKEM_SECRETKEYBYTES);

        // 암호화
        crypto_kem_enc(ct, key_b, pk);
        printf("Ciphertext : ");
        printbytes(ct, MLKEM_CIPHERTEXTBYTES);
        printf("Shared Secret (B) : ");
        printbytes(key_b, MLKEM_SSBYTES);

        // 복호화
        crypto_kem_dec(key_a, ct, sk);
        printf("Shared Secret (A) : ");
        printbytes(key_a, MLKEM_SSBYTES);

        // 공유 비밀 검증
        for (j = 0; j < MLKEM_SSBYTES; j++) {
            if (key_a[j] != key_b[j]) {
                printf(" ERROR : 공유 비밀 매칭 실패\n");
                return;
            }
        }
        printf(" 테스트 성공 !\n");   
    }
}

int main(void) {
    // 모드 설정 후 테스트 실행
    test_kem_mode(PQC_MODE_1);
    return 0;
}