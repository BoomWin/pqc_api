#ifndef _KMU_PQC_EXTERN_H_
#define _KMU_PQC_EXTERN_H_


// 뭔지 모르지만 이거
#ifdef _MSC_VER
#define KMU_PQC_DL_EXPORT    __declspec(dllexport) extern
#else
#define KMU_PQC_DL_EXPORT    __attribute__((visibility("default"))) extern
#endif

/* Kyber 키 생성 함수 */
KMU_PQC_DL_EXPORT unsigned int KMU_PQC_Gen_Key_Kyber(
    unsigned char* pPublicKey,
    unsigned char* PublicKey_length,
    unsigned char* pSecretKey,
    unsigned int* SecretKey_length,
    unsigned int SecurityLevel);

/* Kyber 캡술화 함수 */
KMU_PQC_DL_EXPORT unsigned int KMU_PQC_Encapsultae_Kyber(
    unsigned char* pCiphertext,
    unsigned int* Ciphertext_length,
    unsigned char* pSharedSecret,
    unsigned int* SharedSecret_length,
    unsigned char* pPublicKey,
    unsigned int PublicKey_length,
    unsigned int SecurityLevel);

/* Kyber 디캡슐화 함수 */
KMU_PQC_DL_EXPORT unsigned int KMU_PQC_Decapsulate_Kyber(
    unsigned char* pSharedSecret,
    unsigned int* SharedSecret_length,
    unsigned char* pCiphertext, 
    unsigned int Ciphertext_length,
    unsigned char* pSecretKey,
    unsigned int SecretKey_length,
    unsigned int SecurityLevel);

/* Dilithium 키 생성 함수 */
KMU_PQC_DL_EXPORT unsigned int KMU_PQC_Gen_Key_Dilithium(
    unsigned char* pPublicKey,
    unsigned int* PublicKey_length,
    unsigned char* pSecretKey,
    unsigned int* SecretKey_length,
    unsigned int SecurityLevel);

/* Dilithium 서명 함수 */
KMU_PQC_DL_EXPORT unsigned int KMU_PQC_Sign_Dilithium(
    unsigned char* pSignature,
    unsigned int* Signature_length,
    unsigned char* pMsg,
    unsigned int Msg_length,
    unsigned char* pSecretKey,
    unsigned int SecretKey_length,
    unsigned int SecurityLevel);
