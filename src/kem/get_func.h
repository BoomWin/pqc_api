#include "../../include/pqc_params.h"
#include "./ml-kem-512/clean/polyvec.h"

// 모드에 따른 K 값 반환
static inline int get_mlkem_k(PQC_MODE mode);

// 모드에 따른 ETA1 값 반환
static inline int get_mlkem_eta1(PQC_MODE mode);

// 모드에 따른 ETA2 값 반환
static inline int get_mlkem_eta2(PQC_MODE mode);

// 모드에 따른 POLYCOMPRESSEDBYTES 값 반환
static inline size_t get_mlkem_polycompressedbytes(PQC_MODE mode);

// 모드에 따른 POLYVECCOMPRESSEDBYTES 값 반환
static inline size_t get_mlkem_polyveccompressedbytes(PQC_MODE mode);

// 모드에 따른 POLYVECBYTES 값 반환
static inline size_t get_mlkem_polyvecbytes(PQC_MODE mode);

// 모드에 따른 INDCPA_MSGBYTES 값 반환
static inline size_t get_mlkem_indcpa_msgbytes(PQC_MODE mode);

// 모드에 따른 INDCPA_PUBLICKEYBYTES 값 반환
static inline size_t get_mlkem_indcpa_publickeybytes(PQC_MODE mode);

// 모드에 따른 INDCPA_SECRETKEYBYTES 값 반환
static inline size_t get_mlkem_indcpa_secretkeybytes(PQC_MODE mode);

// 모드에 따른 PUBLIC_KEY_BYTES 값 반환
static inline size_t get_mlkem_publickeybytes(PQC_MODE mode);

// 모드에 따른 SECRET_KEY_BYTES 값 반환
static inline size_t get_mlkem_secretkeybytes(PQC_MODE mode);

// 모드에 따른 CIPHERTEXT_BYTES 값 반환
static inline size_t get_mlkem_ciphertextbytes(PQC_MODE mode);