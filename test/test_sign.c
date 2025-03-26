#include <stdio.h>
#include <string.h>
#include "../include/pqc_sign.h"

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int test_ml_dsa_44(void) {
    uint8_t pk[ML_DSA_44_PUBLIC_KEY_BYTES];
    uint8_t sk[ML_DSA_44_SECRET_KEY_BYTES];
    uint8_t sig[ML_DSA_44_SIGNATURE_BYTES];
    size_t sig_len;
    const uint8_t msg[] = "Test message for ML-DSA-44";
    int ret;

    printf("\nTesting ML-DSA-44...\n");

    // Key generation
    ret = ml_dsa_44_keypair_gen(pk, sk);
    if (ret != 0) {
        printf("Key generation failed!\n");
        return -1;
    }
    printf("Key generation successful\n");

    // Signing
    ret = ml_dsa_44_sign(sig, &sig_len, msg, strlen((char*)msg), sk);
    if (ret != 0) {
        printf("Signature generation failed!\n");
        return -1;
    }
    printf("Signature generation successful\n");

    // Verification
    ret = ml_dsa_44_verify(sig, sig_len, msg, strlen((char*)msg), pk);
    if (ret != 0) {
        printf("Signature verification failed!\n");
        return -1;
    }
    printf("Signature verification successful - Test passed!\n");

    return 0;
}

int main(void) {
    printf("Starting signature tests...\n");
    
    if (test_ml_dsa_44() != 0) {
        printf("ML-DSA-44 test failed!\n");
        return -1;
    }

    printf("\nAll signature tests passed successfully!\n");
    return 0;
}
