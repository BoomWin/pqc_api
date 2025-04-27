#ifndef GET_FUNC_H
#define GET_FUNC_H

#include "../../include/pqc_params.h"
#include "polyvec.h"

// 모드에 따른 K 값 반환
int get_mlkem_k(int mode);

// 모드에 따른 ETA1 값 반환
int get_mlkem_eta1(int mode);

// 모드에 따른 ETA2 값 반환
int get_mlkem_eta2(int mode);

// 모드에 따른 POLYCOMPRESSEDBYTES 값 반환
size_t get_mlkem_polycompressedbytes(int mode);

// 모드에 따른 POLYVECCOMPRESSEDBYTES 값 반환
size_t get_mlkem_polyveccompressedbytes(int mode);

// 모드에 따른 POLYVECBYTES 값 반환
size_t get_mlkem_polyvecbytes(int mode);

// 모드에 따른 INDCPA_MSGBYTES 값 반환
size_t get_mlkem_indcpa_msgbytes(int mode);

// 모드에 따른 INDCPA_PUBLICKEYBYTES 값 반환
size_t get_mlkem_indcpa_publickeybytes(int mode);

// 모드에 따른 INDCPA_SECRETKEYBYTES 값 반환
size_t get_mlkem_indcpa_secretkeybytes(int mode);

// 모드에 따른 PUBLIC_KEY_BYTES 값 반환
size_t get_mlkem_publickeybytes(int mode);

// 모드에 따른 SECRET_KEY_BYTES 값 반환
size_t get_mlkem_secretkeybytes(int mode);

// 모드에 따른 CIPHERTEXT_BYTES 값 반환
size_t get_mlkem_ciphertextbytes(int mode);

#endif