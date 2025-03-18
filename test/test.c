#include "../ml_crypto.h"
 // randombytes 함수를 위한 헤더 추가

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>


#define NTESTS 5

#define MAXLEN 2048
// randombytes 함수 프로토타입 선언 추가
void randombytes(uint8_t *mi, int i);

static void printbytes(const uint8_t *x, size_t xlen) {
    size_t i;
    for (i = 0; i < xlen; i++) {
        printf("%02x", x[i]);
    }
    printf("\n");
}

// 함수 구현부
void randombytes(uint8_t *mi, int i) {
    // 첫 호출 시 난수 생성기 초기화
    static int initialized = 0;
    if (!initialized) {
        srand((unsigned int)time(NULL));
        initialized = 1;
    }
    
    // i 길이만큼 랜덤 바이트 생성
    for (int j = 0; j < i; j++) {
        mi[j] = (uint8_t)(rand() % 256);
    }
}


int main() {
    // 셀렉옵션으로 선택된 값에 한하여 수행.
    //  그냥 지금 정의해서 웹에서도 그 번호를 보내는 형태로 구현하자
    int select = 0;
    printf(" (1) ml-kem-512, (2) ml-kem-768, (3) ml-kem-1024\n");
    printf(" (4) ml-dsa-44,  (2) ml-dsa-65,  (3) ml-dsa-87 \n");
    // 옵션 떄문에 리턴처리 안해주면 오류 정상 반환 값이 1
    if (scanf("%d", &select) != 1) {
        printf("입력 오류 \n");
        return 1;
    }
    if (select == 1) {
    // ML-KEM-512 사용 예시
    uint8_t key_a[ML_KEM_512_CRYPTO_BYTES];
    uint8_t key_b[ML_KEM_512_CRYPTO_BYTES];
    uint8_t pk[ML_KEM_512_PUBLIC_KEY_BYTES];
    uint8_t sendb[ML_KEM_512_CIPHERTEXT_BYTES];
    uint8_t sk_a[ML_KEM_512_SECRET_KEY_BYTES];

    int i;
        for (i = 0; i < NTESTS; i++) {
            // key-pair 생성
            printf("========== ML-KEM-512-keypair-gen ==========\n");
            ml_kem_512_keypair_gen(pk, sk_a);

            printf (" pk : ");
            printbytes(pk, ML_KEM_512_PUBLIC_KEY_BYTES);
            printf (" sk : ");
            printbytes(sk_a, ML_KEM_512_SECRET_KEY_BYTES);

            // 캡슐화
            // encapsulation 
            printf("========== ML-KEM-512-encapsulation ==========\n");
            ml_kem_512_encaps(sendb, key_b, pk);
            printf (" sendb : ");
            printbytes(sendb, ML_KEM_512_CIPHERTEXT_BYTES);
            printf (" key_b : ");
            printbytes(key_b, ML_KEM_512_CRYPTO_BYTES);

            // 복호화
            printf("========== ML-KEM-512-decapsulation ==========\n");
            ml_kem_512_decaps(key_a, sendb, sk_a);
            printf (" key_a : ");
            printbytes(key_a, ML_KEM_512_CRYPTO_BYTES);
        }
    }

    else if (select == 2) {
        // ML-KEM-768
        uint8_t key_a[ML_KEM_768_SHARED_SECRET_BYTES];
        uint8_t key_b[ML_KEM_768_SHARED_SECRET_BYTES];
        uint8_t pk[ML_KEM_768_PUBLIC_KEY_BYTES];
        uint8_t sendb[ML_KEM_768_CIPHERTEXT_BYTES];
        uint8_t sk[ML_KEM_768_SECRET_KEY_BYTES];

        int i;
        for (i = 0; i < NTESTS; i++) {
            // key-pair 생성
            printf("========== ML-KEM-768-keypair-gen ==========\n");
            ml_kem_768_keypair_gen(pk, sk);

            printf("pk : ");
            printbytes(pk, ML_KEM_768_PUBLIC_KEY_BYTES);
            printf("sk : ");
            printbytes(sk, ML_KEM_768_SECRET_KEY_BYTES);

            // encapsulation
            printf("========== ML-KEM-768-encaps ==========\n");
            ml_kem_768_encaps(sendb, key_b, pk);
            printf(" sendb : ");
            printbytes(sendb, ML_KEM_768_CIPHERTEXT_BYTES);
            printf(" key_b : ");
            printbytes(key_b, ML_KEM_768_SHARED_SECRET_BYTES);

            // decapsulation
            printf("========== ML-KEM-768-decaps ==========\n");
            ml_kem_768_decaps(key_a, sendb, sk);
            printf(" key_a : ");
            printbytes(key_a, ML_KEM_768_SHARED_SECRET_BYTES);
            
        }
    }

    else if(select == 3) {
        // ML-KEM 1024 수행
        uint8_t key_a[ML_KEM_1024_SHARED_SECRET_BYTES];
        uint8_t key_b[ML_KEM_1024_SHARED_SECRET_BYTES];
        uint8_t sendb[ML_KEM_1024_CIPHERTEXT_BYTES];
        uint8_t pk[ML_KEM_1024_PUBLIC_KEY_BYTES];
        uint8_t sk[ML_KEM_1024_SECRET_KEY_BYTES];

        int i;
        for (i = 0; i < NTESTS; i++) {
            printf("========== ML-KEM-1024-keypair-gen ==========\n");
            ml_kem_1024_keypair_gen(pk, sk);

            printf("pk : ");
            printbytes(pk, ML_KEM_1024_PUBLIC_KEY_BYTES);
            printf("sk : ");
            printbytes(sk, ML_KEM_1024_SECRET_KEY_BYTES);

            printf("========== ML-KEM-1024-encaps ==========\n");
            ml_kem_1024_encaps(sendb, key_b, pk);
            printf(" sendb : ");
            printbytes(sendb, ML_KEM_1024_CIPHERTEXT_BYTES);
            printf(" key_b : ");
            printbytes(key_b, ML_KEM_1024_SHARED_SECRET_BYTES);

            printf("========== ML-KEM-1024-decaps ==========\n");
            ml_kem_1024_decaps(key_a, sendb, sk);
            printf(" key_a : ");
            printbytes(key_a, ML_KEM_1024_SHARED_SECRET_BYTES);

        }
    }

    else if(select == 4) {
        uint8_t sk[ML_DSA_44_SECRET_KEY_BYTES];
        uint8_t pk[ML_DSA_44_PUBLIC_KEY_BYTES];

        uint8_t mi[MAXLEN];
        uint8_t sm[MAXLEN + ML_DSA_44_SIGNATURE_BYTES];
        uint8_t sig[ML_DSA_44_SIGNATURE_BYTES];

        size_t smlen;
        size_t siglen;
        size_t mlen;

        int r;
        size_t i, k;

        /* i = 0, 1, 4, 16, 64, 256, 1024 */
        for (i = 0; i < MAXLEN; i = (i == 0) ? i + 1 : i << 2) {
            randombytes(mi, i);

            ml_dsa_44_keypair_gen(pk, sk);

            printf(" Public Key : ");
            printbytes(pk, ML_DSA_44_PUBLIC_KEY_BYTES);
            printf(" Secret Key : ");
            printbytes(sk, ML_DSA_44_SECRET_KEY_BYTES);

            ml_dsa_44_sign_message(sm, &smlen, mi, i, sk);
            ml_dsa_44_sign(sig, &siglen, mi, i, sk);

            printf( " Signature + Message : ");
            printbytes(sm, smlen);
            printf(" Signature ");
            printbytes(sig, siglen);

            r = ml_dsa_44_open_message(sm, &mlen, sm, smlen, pk);
            r |= ml_dsa_44_verify(sig, siglen, mi, i, pk);

            if (r) {
                printf(" ERROR : Signature Verification Failed \n");
                return -1;
            }
            for (k = 0; k < i; k++) {
                if (sm[k] != mi[k]) {
                    printf("ERROR : Message Recovery Failed\n");
                    return -1;
                }
            }
        }
       
    }

    return 0;
}