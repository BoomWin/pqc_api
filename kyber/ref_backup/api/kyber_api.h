#ifndef KYBER_API_H
#define KYBER_API_H

#include <stdint.h>
#include <stddef.h>

// API 버전 정보
#define KYBER_API_VERSION "1.0.0"

// Kyber 보안 레벨 상수
#define KYBER_SECURITY_LEVEL_512 2
#define KYBER_SECURITY_LEVEL_768 3
#define KYBER_SECURITY_LEVEL_1024 4

// 키 크기 상수 (실제 값은 보안 레벨에 따라 달라진다.)
extern size_t KYBER_PUBLIC_KEY_BYTES;
extern size_t KYBER_SECRET_KEY_BYTES;
extern size_t KYBER_CIPHERTEXT_BYTES;
extern size_t KYBER_SHARED_SECRET_BYTES;

// 초기화 함수
int kyber_init(int security_level);

// 키 생성 함수
int kyber_keypair(uint8_t *public_key, 
                  uint8_t *secret_key);

// 암호화 함수
int kyber_encrypt(uint8_t *ciphertext, 
                  uint8_t *shared_secret, 
                  const uint8_t *public_key);

// 복호화 함수
int kyber_decrypt(uint8_t *shared_secret,
                  const uint8_t *ciphertext,
                  const uint8_t *secret_key);

// 오류 코드
#define KYBER_SUCCESS 0 
#define KYBER_ERROR_INVALID_SECURITY_LEVEL -1
#define KYBER_ERROR_UNINITIALIZED -2
#define KYBER_ERROR_INVALID_PARAMETER -3

#endif // KYBER_API_H