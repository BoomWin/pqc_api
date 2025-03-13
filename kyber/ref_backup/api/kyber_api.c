#include "kyber_api.h"
#include "api.h"
#include "randombytes.h"

// 전역 변수 초기화
static int kyber_initialized = 0;
static int current_security_level = 0;

// 키 크기 상수 (초기값은 0, 초기화 시 설정됨)
size_t KYBER_PUBLIC_KEY_BYTES = 0;
size_t KYBER_SECRET_KEY_BYTES = 0;
size_t KYBER_CIPHERTEXT_BYTES = 0;
size_t KYBER_SHARED_SECRET_BYTES = 0;

// 내부 함수 선언

int kyber_init(int security_level) {
    // 보안 레벨 검증
    if (security_level != KYBER_SECURITY_LEVEL_512 &&
        security_level != KYBER_SECURITY_LEVEL_768 &&
        security_level != KYBER_SECURITY_LEVEL_1024) {
        return KYBER_ERROR_INVALID_SECURITY_LEVEL;
    }

    // 보안 레벨에 따른 키 크기 설정
    current_security_level = security_level;
    
    // 각 보안 레벨에 따라 키 크기 설정
    if (security_level == KYBER_SECURITY_LEVEL_512) {
        KYBER_PUBLIC_KEY_BYTES = pqcrystals_kyber512_PUBLICKEYBYTES;
        KYBER_SECRET_KEY_BYTES = pqcrystals_kyber512_SECRETKEYBYTES;
        KYBER_CIPHERTEXT_BYTES = pqcrystals_kyber512_CIPHERTEXTBYTES;
        KYBER_SHARED_SECRET_BYTES = pqcrystals_kyber512_BYTES;
    } 
    else if (security_level == KYBER_SECURITY_LEVEL_768) {
        KYBER_PUBLIC_KEY_BYTES = pqcrystals_kyber768_PUBLICKEYBYTES;
        KYBER_SECRET_KEY_BYTES = pqcrystals_kyber768_SECRETKEYBYTES;
        KYBER_CIPHERTEXT_BYTES = pqcrystals_kyber768_CIPHERTEXTBYTES;
        KYBER_SHARED_SECRET_BYTES = pqcrystals_kyber768_BYTES;
    }
    else { // KYBER_SECURITY_LEVEL_1024
        KYBER_PUBLIC_KEY_BYTES = pqcrystals_kyber1024_PUBLICKEYBYTES;
        KYBER_SECRET_KEY_BYTES = pqcrystals_kyber1024_SECRETKEYBYTES;
        KYBER_CIPHERTEXT_BYTES = pqcrystals_kyber1024_CIPHERTEXTBYTES;
        KYBER_SHARED_SECRET_BYTES = pqcrystals_kyber1024_BYTES;
    }
    
    // 초기화 잘 수행되었으면 1로 설정해서 이후 동작들에 영향을 준다.
    kyber_initialized = 1;
    return KYBER_SUCCESS;
}

// 키 생성 함수
int kyber_keypair(uint8_t *public_key, uint8_t *secret_key) {
    // 초기화 여부 확인
    if (!kyber_initialized) {
        return KYBER_ERROR_UNINITIALIZED;
    }

    // 매개변수 검증
    if (public_key == NULL || secret_key == NULL) {
        return KYBER_ERROR_INVALID_PARAMETER;
    }

      // 보안 레벨에 따라 적절한 함수 호출
    switch (current_security_level) {
        case KYBER_SECURITY_LEVEL_512:
            return pqcrystals_kyber512_ref_keypair(public_key, secret_key);
        case KYBER_SECURITY_LEVEL_768:
            return pqcrystals_kyber768_ref_keypair(public_key, secret_key);
        case KYBER_SECURITY_LEVEL_1024:
            return pqcrystals_kyber1024_ref_keypair(public_key, secret_key);
        default:
            return KYBER_ERROR_INVALID_SECURITY_LEVEL;
    }
}

// 암호화 함수  
int kyber_encrypt(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
    // 초기화 여부 확인
    if (!kyber_initialized) {
        return KYBER_ERROR_UNINITIALIZED;
    }
    
    // 매개변수 검증
    if (ciphertext == NULL || shared_secret == NULL || public_key == NULL) {
        return KYBER_ERROR_INVALID_PARAMETER;
    }
    
    // 보안 레벨에 따라 적절한 함수 호출
    switch (current_security_level) {
        case KYBER_SECURITY_LEVEL_512:
            return pqcrystals_kyber512_ref_enc(ciphertext, shared_secret, public_key);
        case KYBER_SECURITY_LEVEL_768:
            return pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key);
        case KYBER_SECURITY_LEVEL_1024:
            return pqcrystals_kyber1024_ref_enc(ciphertext, shared_secret, public_key);
        default:
            return KYBER_ERROR_INVALID_SECURITY_LEVEL;
    }
}

// 복호화 함수
int kyber_decrypt(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
    // 초기화 여부 확인
    if (!kyber_initialized) {
        return KYBER_ERROR_UNINITIALIZED;
    }
    
    // 매개변수 검증
    if (shared_secret == NULL || ciphertext == NULL || secret_key == NULL) {
        return KYBER_ERROR_INVALID_PARAMETER;
    }
    
    // 보안 레벨에 따라 적절한 함수 호출
    switch (current_security_level) {
        case KYBER_SECURITY_LEVEL_512:
            return pqcrystals_kyber512_ref_dec(shared_secret, ciphertext, secret_key);
        case KYBER_SECURITY_LEVEL_768:
            return pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
        case KYBER_SECURITY_LEVEL_1024:
            return pqcrystals_kyber1024_ref_dec(shared_secret, ciphertext, secret_key);
        default:
            return KYBER_ERROR_INVALID_SECURITY_LEVEL;
    }
}