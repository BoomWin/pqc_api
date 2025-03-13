#ifndef _KMU_PQC_DEFINE_H_
#define _KMU_PQC_DEFINE_H_

/* 반환 코드 정의 */
#define KM_PQC_OK               0x00000000
#define KM_PQC_DEFAULT_ERROR    0xFFFFFFFF
#define KM_PQC_INVALID_PARAM    0x00000001
#define KM_PQC_MEMORY_ERROR     0x00000002
#define KM_PQC_VERIFICATION_FAILED 0x00000004

/* 알고리즘 정의 */
#define KM_PQC_ALG_KYBER                           1
#define KM_PQC_ALG_DILITHIUM                       2

/* Kyber 보안 레벨 정의  */ 
#define KM_PQC_KYBER_SECURITY_LEVEL_512            2
#define KM_PQC_KYBER_SECURITY_LEVEL_768            3
#define KM_PQC_KYBER_SECURITY_LEVEL_1024           4

/* Kyber 키 크기 상수 (바이트 단위) */
/* Kyber-512 */
#define KM_PQC_KYBER_512_PUBLIC_KEY_BYTES          800
#define KM_PQC_KYBER_512_SECRET_KEY_BYTES          1632
#define KM_PQC_KYBER_512_CIPHERTEXT_BYTES          768
#define KM_PQC_KYBER_512_SHARED_SECRET_BYTES       32

/* Kyber-768 */
#define KM_PQC_KYBER_768_PUBLIC_KEY_BYTES          1184
#define KM_PQC_KYBER_768_SECRET_KEY_BYTES          2400
#define KM_PQC_KYBER_768_CIPHERTEXT_BYTES          1088
#define KM_PQC_KYBER_768_SHARED_SECRET_BYTES       32

/* Kyber-1024 */
#define KM_PQC_KYBER_1024_PUBLIC_KEY_BYTES         1568
#define KM_PQC_KYBER_1024_SECRET_KEY_BYTES         3168
#define KM_PQC_KYBER_1024_CIPHERTEXT_BYTES         1568
#define KM_PQC_KYBER_1024_SHARED_SECRET_BYTES      32

/* Dilithium 키 크기 상수 (바이트 단위) */
/* Dilithium-2 */
#define KM_PQC_DILITHIUM_2_PUBLIC_KEY_BYTES        1312
#define KM_PQC_DILITHIUM_2_SECRET_KEY_BYTES        2528
#define KM_PQC_DILITHIUM_2_SIGNATURE_BYTES         2420

/* Dilithium-3 */
#define KM_PQC_DILITHIUM_3_PUBLIC_KEY_BYTES        1952
#define KM_PQC_DILITHIUM_3_SECRET_KEY_BYTES        4000
#define KM_PQC_DILITHIUM_3_SIGNATURE_BYTES         3293

/* Dilithium-5 */
#define KM_PQC_DILITHIUM_5_PUBLIC_KEY_BYTES        2592
#define KM_PQC_DILITHIUM_5_SECRET_KEY_BYTES        4864
#define KM_PQC_DILITHIUM_5_SIGNATURE_BYTES         4595

#endif /* _KMU_PQC_DEFINE_H_ */