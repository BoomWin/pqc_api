#include <stdio.h>
#include <string.h>
#include "../include/pqc_kem.h"

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int test_ml_kem_512(void) {
    uint8_t pk[ML_KEM_512_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_KEM_512_SECRET_KEY_BYTES];
    uint8_t ct[ML_KEM_512_CIPHERTEXT_BYTES];
    uint8_t ss1[ML_KEM_512_SHARED_SECRET_BYTES];
    uint8_t ss2[ML_KEM_512_SHARED_SECRET_BYTES];
    int ret;

    printf("\nTesting ML-KEM-512...\n");

    // Key generation
    ret = ml_kem_512_keypair_gen(pk, sk);
    if (ret != 0) {
        printf("Key generation failed!\n");
        return -1;
    }
    printf("Key generation successful\n");

    // Encapsulation
    ret = ml_kem_512_encaps(ct, ss1, pk);
    if (ret != 0) {
        printf("Encapsulation failed!\n");
        return -1;
    }
    printf("Encapsulation successful\n");

    // Decapsulation
    ret = ml_kem_512_decaps(ss2, ct, sk);
    if (ret != 0) {
        printf("Decapsulation failed!\n");
        return -1;
    }
    printf("Decapsulation successful\n");

    // Compare shared secrets
    if (memcmp(ss1, ss2, ML_KEM_512_SHARED_SECRET_BYTES) != 0) {
        printf("Shared secrets do not match!\n");
        return -1;
    }
    
    print_hex("Shared Secret 1", ss1, ML_KEM_512_SHARED_SECRET_BYTES);
    print_hex("Shared Secret 2", ss2, ML_KEM_512_SHARED_SECRET_BYTES);
    printf("Shared secrets match - Test passed!\n");

    return 0;
}

int main(void) {
    printf("Starting KEM tests...\n");
    
    if (test_ml_kem_512() != 0) {
        printf("ML-KEM-512 test failed!\n");
        return -1;
    }

    printf("\nAll KEM tests passed successfully!\n");
    return 0;
} 