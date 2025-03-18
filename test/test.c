#include "../ml_crypto.h"
#include <stdio.h>

int main() {
    // ML-KEM-512 사용 예시
    uint8_t pk[ML_KEM_512_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_KEM_512_SECRET_KEY_BYTES];
    uint8_t ct[ML_KEM_512_CIPHERTEXT_BYTES];
    uint8_t ss[ML_KEM_512_SHARED_SECRET_BYTES];
    uint8_t ss2[ML_KEM_512_SHARED_SECRET_BYTES];

    // 키 생성
    if (ml_kem_512_keypair_gen(pk, sk) != 0) {
        printf("키 생성 실패\n");
        return -1;
    }

    // 캡슐화

    

    return 0;
}