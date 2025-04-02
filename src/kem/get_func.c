#include "get_func.h"

// 모드에 따른 K 값 반환
static inline int get_mlkem_k(PQC_MODE mode) {
    if (mode == PQC_MODE_1) return MLKEM_512_K;
    else if (mode == PQC_MODE_2) return MLKEM_768_K;
    else if (mode == PQC_MODE_3) return MLKEM_1024_K;
    return 0; // 오류 케이스
}

// 모드에 따른 ETA1 값 반환
static inline int get_mlkem_eta1(PQC_MODE mode) {
    if (mode == PQC_MODE_1) return MLKEM_512_ETA1;
    else if (mode == PQC_MODE_2) return MLKEM_768_ETA1;
    else if (mode == PQC_MODE_3) return MLKEM_1024_ETA1;
    return 0; // 오류 케이스
}

// 모드에 따른 ETA2 값 반환
static inline int get_mlkem_eta2(PQC_MODE mode) {
    if (mode == PQC_MODE_1) return MLKEM_512_ETA2;
    else if (mode == PQC_MODE_2) return MLKEM_768_ETA2;
    else if (mode == PQC_MODE_3) return MLKEM_1024_ETA2;
    return 0; // 오류 케이스
}

// 모드에 따른 POLYCOMPRESSEDBYTES 값 반환
static inline size_t get_mlkem_polycompressedbytes(PQC_MODE mode) {
    if (mode == PQC_MODE_1) return MLKEM_512_POLYCOMPRESSEDBYTES;
    else if (mode == PQC_MODE_2) return MLKEM_768_POLYCOMPRESSEDBYTES;
    else if (mode == PQC_MODE_3) return MLKEM_1024_POLYCOMPRESSEDBYTES;
    return 0; // 오류 케이스
}

// 모드에 따른 POLYVECCOMPRESSEDBYTES 값 반환
static inline size_t get_mlkem_polyveccompressedbytes(PQC_MODE mode) {
    if (mode == PQC_MODE_1) return MLKEM_512_POLYVECCOMPRESSEDBYTES;
    else if (mode == PQC_MODE_2) return MLKEM_768_POLYVECCOMPRESSEDBYTES;
    else if (mode == PQC_MODE_3) return MLKEM_1024_POLYVECCOMPRESSEDBYTES;
    return 0; // 오류 케이스
}

// 모드에 따른 POLYVECBYTES 값 반환
static inline size_t get_mlkem_polyvecbytes(PQC_MODE mode) {
    if (mode == PQC_MODE_1) return MLKEM_512_POLYVECBYTES;
    else if (mode == PQC_MODE_2) return MLKEM_768_POLYVECBYTES;
    else if (mode == PQC_MODE_3) return MLKEM_1024_POLYVECBYTES;
    return 0; // 오류 케이스
}

// 모드에 따른 INDCPA_MSGBYTES 값 반환
static inline size_t get_mlkem_indcpa_msgbytes(PQC_MODE mode) {
    if (mode == PQC_MODE_1) return MLKEM_512_INDCPA_MSGBYTES;
    else if (mode == PQC_MODE_2) return MLKEM_768_INDCPA_MSGBYTES;
    else if (mode == PQC_MODE_3) return MLKEM_1024_INDCPA_MSGBYTES;
    return 0; // 오류 케이스
}

// 모드에 따른 INDCPA_PUBLICKEYBYTES 값 반환
static inline size_t get_mlkem_indcpa_publickeybytes(PQC_MODE mode) {
    if (mode == PQC_MODE_1) return MLKEM_512_INDCPA_PUBLICKEYBYTES;
    else if (mode == PQC_MODE_2) return MLKEM_768_INDCPA_PUBLICKEYBYTES;
    else if (mode == PQC_MODE_3) return MLKEM_1024_INDCPA_PUBLICKEYBYTES;
    return 0; // 오류 케이스
}

// 모드에 따른 INDCPA_SECRETKEYBYTES 값 반환
static inline size_t get_mlkem_indcpa_secretkeybytes(PQC_MODE mode) {
    if (mode == PQC_MODE_1) return MLKEM_512_INDCPA_SECRETKEYBYTES;
    else if (mode == PQC_MODE_2) return MLKEM_768_INDCPA_SECRETKEYBYTES;
    else if (mode == PQC_MODE_3) return MLKEM_1024_INDCPA_SECRETKEYBYTES;
    return 0; // 오류 케이스
}

// 모드에 따른 PUBLIC_KEY_BYTES 값 반환
static inline size_t get_mlkem_publickeybytes(PQC_MODE mode) {
    if (mode == PQC_MODE_1) return ML_KEM_512_PUBLIC_KEY_BYTES;
    else if (mode == PQC_MODE_2) return ML_KEM_768_PUBLIC_KEY_BYTES;
    else if (mode == PQC_MODE_3) return ML_KEM_1024_PUBLIC_KEY_BYTES;
    return 0; // 오류 케이스
}

// 모드에 따른 SECRET_KEY_BYTES 값 반환
static inline size_t get_mlkem_secretkeybytes(PQC_MODE mode) {
    if (mode == PQC_MODE_1) return ML_KEM_512_SECRET_KEY_BYTES;
    else if (mode == PQC_MODE_2) return ML_KEM_768_SECRET_KEY_BYTES;
    else if (mode == PQC_MODE_3) return ML_KEM_1024_SECRET_KEY_BYTES;
    return 0; // 오류 케이스
}

// 모드에 따른 CIPHERTEXT_BYTES 값 반환
static inline size_t get_mlkem_ciphertextbytes(PQC_MODE mode) {
    if (mode == PQC_MODE_1) return ML_KEM_512_CIPHERTEXT_BYTES;
    else if (mode == PQC_MODE_2) return ML_KEM_768_CIPHERTEXT_BYTES;
    else if (mode == PQC_MODE_3) return ML_KEM_1024_CIPHERTEXT_BYTES;
    return 0; // 오류 케이스
}