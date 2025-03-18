#include "../ml_crypto.h"
#include <stdio.h>

#define NTESTS 5

static void printbytes(const uint8_t *x, size_t xlen) {
    size_t i;
    for (i = 0; i < xlen; i++) {
        printf("%02x", x[i]);
    }
    printf("\n");
}

int main() {
    // ML-KEM-512 사용 예시
    uint8_t key_a[ML_KEM_512_CRYPTO_BYTES];
    uint8_t key_b[ML_KEM_512_CRYPTO_BYTES];
    uint8_t pk[ML_KEM_512_PUBLIC_KEY_BYTES];
    uint8_t sendb[ML_KEM_512_CIPHERTEXT_BYTES];
    uint8_t sk_a[ML_KEM_512_SECRET_KEY_BYTES];
    int i, j;
    for (i = 0; i < NTESTS; i++) {
        // key-pair 생성
        ml_kem_512_keypair_gen(pk, sk_a);

        printf (" pk : ");
        printbytes(pk, ML_KEM_512_PUBLIC_KEY_BYTES);
        printf (" sk : ");
        printbytes(sk_a, ML_KEM_512_SECRET_KEY_BYTES);

        // 캡슐화
        // encapsulation 
        ml_kem_512_encaps(sendb, key_b, pk);
        printf (" sendb : ");
        printbytes(sendb, ML_KEM_512_CIPHERTEXT_BYTES);
        printf (" key_b : ");
        printbytes(key_b, ML_KEM_512_CRYPTO_BYTES);

        // 복호화
        ml_kem_512_decaps(key_a, sendb, sk_a);
        printf (" key_a : ");
        printbytes(key_a, ML_KEM_512_CRYPTO_BYTES);
        
    }
    

    // uint8_t pk[ML_KEM_512_PUBLIC_KEY_BYTES];
    // uint8_t sk[ML_KEM_512_SECRET_KEY_BYTES];
    // uint8_t ct[ML_KEM_512_CIPHERTEXT_BYTES];
    // uint8_t ss[ML_KEM_512_SHARED_SECRET_BYTES];
    // uint8_t ss2[ML_KEM_512_SHARED_SECRET_BYTES];

    // 키 생성
    // if (ml_kem_512_keypair_gen(pk, sk) != 0) {
    //     printf("키 생성 실패\n");
    //     return -1;
    // }
    // printf("키 생성 성공\n");
    // 캡슐화

    

    return 0;
}