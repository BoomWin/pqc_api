#include "../ml_crypto.h"
#include "../common/randombytes.h"
 // randombytes 함수를 위한 헤더 추가

#include <stdio.h>
#include <string.h>
#include <stdlib.h>



// randombytes 함수 프로토타입 선언 추가
// void randombytes(uint8_t *mi, int i);

static void printbytes(const uint8_t *x, size_t xlen) {
    size_t i;
    for (i = 0; i < xlen; i++) {
        printf("%02x", x[i]);
    }
    printf("\n");
}

int main() {
    // 셀렉옵션으로 선택된 값에 한하여 수행.
    //  그냥 지금 정의해서 웹에서도 그 번호를 보내는 형태로 구현하자
    int select = 0;
    printf(" (1) ml-kem-512, (2) ml-kem-768, (3) ml-kem-1024\n");
    printf(" (4) ml-dsa-44,  (5) ml-dsa-65,  (6) ml-dsa-87 \n");
    printf(" (7)  sphincs-sha2-128f,  (8)  sphincs-sha2-128s\n");
    printf(" (9)  sphincs-sha2-192f,  (10) sphincs-sha2-192s\n");
    printf(" (11) sphincs-sha2-256f,  (12) sphincs-sha2-256s\n ");
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
            printf(" ORIGINAL MESSAGE : ");
            printbytes(mi, i);

            ml_dsa_44_keypair_gen(pk, sk);

            printf(" Public Key : ");
            printbytes(pk, ML_DSA_44_PUBLIC_KEY_BYTES);
            printf(" Secret Key : ");
            printbytes(sk, ML_DSA_44_SECRET_KEY_BYTES);

            ml_dsa_44_sign_message(sm, &smlen, mi, i, sk);
            ml_dsa_44_sign(sig, &siglen, mi, i, sk);

            printf(" Signature + Message : ");
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
                    printf(" ERROR : Message Recovery Failed\n");
                    return -1;
                }
            }
        }
       
    }

    else if (select == 5) {
        uint8_t sk[ML_DSA_65_SECRET_KEY_BYTES];
        uint8_t pk[ML_DSA_65_PUBLIC_KEY_BYTES];

        uint8_t mi[MAXLEN];
        uint8_t sm[MAXLEN + ML_DSA_65_SIGNATURE_BYTES];
        uint8_t sig[ML_DSA_65_SIGNATURE_BYTES];

        size_t smlen;
        size_t siglen;
        size_t mlen;

        int r;
        size_t i, k;

        /* i = 0, 1, 4, 16, 64, 256, 1024 */
        for (i = 0; i < MAXLEN; i = (i==0) ? i + 1 : i << 2) {
            randombytes(mi, i);
            printf(" ORIGINAL MESSAGE : ");
            printbytes(mi, i);

            ml_dsa_65_keypair_gen(pk, sk);
            printf(" Pulbic Key : ");
            printbytes(pk, ML_DSA_65_PUBLIC_KEY_BYTES);
            printf(" Secret Key : ");
            printbytes(sk, ML_DSA_65_SECRET_KEY_BYTES);

            ml_dsa_65_sign_message(sm, &smlen, mi, i, sk);
            ml_dsa_65_sign(sig, &siglen, mi, i, sk);

            printf(" Signature + Message : ");
            printbytes(sm, smlen);
            printf(" Signature : ");
            printbytes(sig, siglen);
            
            // 정상 처리 되면 return 값 0반환해서, r이라는 변수 주고 r로 정상 작동 체크
            // 0 이상의 값이 오면 에러임.

            // sm은 현재 [서명 || 원본메시지] 로 되어 있는데 함수 돌게 되면
            // 입력 : sm [서명 || 메시지 ] -> 검증 -> sm [메시지] (메시지만 남게 됨)
            r = ml_dsa_65_open_message(sm, &mlen, sm, smlen, pk);
            r |= ml_dsa_65_verify(sig, siglen, mi, i, pk);

            if (r) {
                printf(" ERROR : Signature Verification Failed \n");
                return -1;
            }
            
            for (k = 0; k < i; k++) {
                if (sm[k] != mi[k]) {
                    printf(" ERROR : Message Recovery Failed\n");
                    return -1;
                }
            }
            printf(" Message Recocvery Success \n");
            printf(" SM (과정 수행후 메시지만 남음) : ");
            printbytes(sm, smlen);

            printf(" M (원래 메시지) : ") ;
            printbytes(mi, mlen);

        }
    }

    else if (select == 6) {
        uint8_t sk[ML_DSA_87_SECRET_KEY_BYTES];
        uint8_t pk[ML_DSA_87_PUBLIC_KEY_BYTES];

        uint8_t mi[MAXLEN];
        uint8_t sm[MAXLEN + ML_DSA_87_SIGNATURE_BYTES];
        uint8_t sig[ML_DSA_87_SIGNATURE_BYTES];

        size_t smlen;
        size_t siglen;
        size_t mlen;

        int r;
        size_t i, k;

        /* i = 0, 1, 4, 16, 64, 256, 1024 */
        for (i = 0; i < MAXLEN; i = (i==0) ? i + 1 : i << 2) {
            randombytes(mi, i);
            printf("Original Message : ");
            printbytes(mi, i);

            ml_dsa_87_keypair_gen(pk, sk);

            printf(" Public Key : ");
            printbytes(pk, ML_DSA_87_PUBLIC_KEY_BYTES);
            printf(" Secret Key : ");
            printbytes(sk, ML_DSA_87_SECRET_KEY_BYTES);

            ml_dsa_87_sign_message(sm, &smlen, mi, i, sk);
            ml_dsa_87_sign(sig, &siglen, mi, i, sk);

            printf("Sig + Message : ");
            printbytes(sm, smlen);
            printf("Sig");
            printbytes(sig, siglen);

            r = ml_dsa_87_open_message(sm, &mlen, sm, smlen, pk);
            r |= ml_dsa_87_verify(sig, siglen, mi, i, pk);

            if (r) {
                printf("ERROR : signature verification failed\n");
                return -1;
            }
            for (k = 0; k < i; k++) {
                if (sm[k] != mi[k]) {
                    printf("ERROR : message recovery failed\n");
                    return -1;
                }
            }
            printf("SUCCESS\n");
        }
    }
    else if(select == 7) {
        uint8_t sk[SPHINCS_SHA2_128F_SECRET_KEY_BYTES];
        uint8_t pk[SPHINCS_SHA2_128F_PUBLIC_KEY_BYTES];

        uint8_t mi[MAXLEN];
        uint8_t sm[MAXLEN + SPHINCS_SHA2_128F_SIGNATURE_BYTES];
        uint8_t sig[SPHINCS_SHA2_128F_SIGNATURE_BYTES];

        size_t smlen;
        size_t siglen;
        size_t mlen;

        int r;
        size_t i, k;

        /* 0 , 1, 4, 16, 64, 256, 1024로 테스트 */
        for(i = 0; i < MAXLEN; i = (i == 0) ? i + 1 : i << 2) {
            randombytes(mi, i);
            printf("Original Message : ");
            printbytes(mi, i);

            // 키 생성
            sphincs_sha2_128f_keypair(pk, sk);
            printf("Public Key : ");
            printbytes(pk, SPHINCS_SHA2_128F_PUBLIC_KEY_BYTES);
            printf("Secret Key : ");
            printbytes(sk, SPHINCS_SHA2_128F_SECRET_KEY_BYTES);

            sphincs_sha2_128f_sign_message(sm, &smlen, mi, i, sk);
            sphincs_sha2_128f_signature(sig, &siglen, mi, i, sk);

            printf("SIGNATURE + MESSAGE : ");
            printbytes(sm, smlen);
            printf("ONLY SIGNATURE : ");
            printbytes(sig, siglen);

            r = sphincs_sha2_128f_open_message(sm, &mlen, sm, smlen, pk);
            r |= sphincs_sha2_128f_verify(sig, siglen, mi, i, pk);

            if (r) {
                printf("ERORR : Signature Verification Failed\n");
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
    else if (select == 8) {
        uint8_t sk[SPHINCS_SHA2_128S_SECRET_KEY_BYTES];
        uint8_t pk[SPHINCS_SHA2_128S_PUBLIC_KEY_BYTES];

        uint8_t mi[MAXLEN];
        uint8_t sm[MAXLEN + SPHINCS_SHA2_128S_SIGNATURE_BYTES];
        uint8_t sig[SPHINCS_SHA2_128S_SIGNATURE_BYTES];

        size_t smlen;
        size_t siglen;
        size_t mlen;

        int r;
        size_t i, k;

        /* 0 , 1, 4, 16, 64, 256, 1024로 테스트 */
        for(i = 0; i < MAXLEN; i = (i == 0) ? i + 1 : i << 2) {
            randombytes(mi, i);
            printf("Original Message : ");
            printbytes(mi, i);

            sphincs_sha2_128s_keypair(pk, sk);
            printf("Public Key : ");
            printbytes(pk, SPHINCS_SHA2_128S_PUBLIC_KEY_BYTES);
            printf("Secret Key : ");
            printbytes(sk, SPHINCS_SHA2_128S_SECRET_KEY_BYTES);

            sphincs_sha2_128s_sign_message(sm, &smlen, mi, i, sk);
            sphincs_sha2_128s_signature(sig, &siglen, mi, i, sk);

            printf("SIGNATURE + MESSAGE : ");
            printbytes(sm, smlen);
            printf("ONLY SIGNATURE : ");
            printbytes(sig, siglen);

            r = sphincs_sha2_128s_open_message(sm, &mlen, sm, smlen, pk);
            r |= sphincs_sha2_128s_verify(sig, siglen, mi, i, pk);      

            if (r) {
                printf("ERROR : Signature Verification Failed\n");
                return -1;
            }
            for (k = 0; k < i; k++) {
                if (sm[k] != mi[k]) {
                    printf("ERROR : Message Recovery Failed\n");
                    return -1;
                }
            }
            printf("SUCCESS\n");
        }
    }
    else if (select == 9) {
        uint8_t sk[SPHINCS_SHA2_192F_SECRET_KEY_BYTES];
        uint8_t pk[SPHINCS_SHA2_192F_PUBLIC_KEY_BYTES];

        uint8_t mi[MAXLEN];
        uint8_t sm[MAXLEN + SPHINCS_SHA2_192F_SIGNATURE_BYTES];
        uint8_t sig[SPHINCS_SHA2_192F_SIGNATURE_BYTES];

        size_t smlen;
        size_t siglen;
        size_t mlen;

        int r;
        size_t i, k;

        /* 0 , 1, 4, 16, 64, 256, 1024로 테스트 */
        for(i = 0; i < MAXLEN; i = (i == 0) ? i + 1 : i << 2) {
            randombytes(mi, i);
            printf("Original Message : ");
            printbytes(mi, i);

            sphincs_sha2_192f_keypair(pk, sk);
            printf("Public Key : ");
            printbytes(pk, SPHINCS_SHA2_192F_PUBLIC_KEY_BYTES);
            printf("Secret Key : ");
            printbytes(sk, SPHINCS_SHA2_192F_SECRET_KEY_BYTES);

            sphincs_sha2_192f_sign_message(sm, &smlen, mi, i, sk);
            sphincs_sha2_192f_signature(sig, &siglen, mi, i, sk);

            printf("SIGNATURE + MESSAGE : ");
            printbytes(sm, smlen);
            printf("ONLY SIGNATURE : ");
            printbytes(sig, siglen);

            r = sphincs_sha2_192f_open_message(sm, &mlen, sm, smlen, pk);
            r |= sphincs_sha2_192f_verify(sig, siglen, mi, i, pk);

            if (r) {
                printf("ERROR : Signature Verification Failed\n");
                return -1;
            }
            for (k = 0; k < i; k++) {
                if (sm[k] != mi[k]) {
                    printf("ERROR : Message Recovery Failed\n");
                    return -1;
                }
            }
            printf("SUCCESS\n");
        }
    }

    return 0;
}