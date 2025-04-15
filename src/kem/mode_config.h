// mode_config.h
#ifndef MODE_CONFIG_H
#define MODE_CONFIG_H

#include <stddef.h>
#include <stdint.h>

// 전역 변수 선언
extern int MLKEM_CURRENT_MODE;

extern int MLKEM_K;
extern int MLKEM_ETA1;
extern int MLKEM_ETA2;
extern size_t MLKEM_POLYCOMPRESSEDBYTES;
extern size_t MLKEM_POLYVECCOMPRESSEDBYTES;
extern size_t MLKEM_POLYVECBYTES;
extern size_t MLKEM_INDCPA_MSGBYTES;
extern size_t MLKEM_INDCPA_PUBLICKEYBYTES;
extern size_t MLKEM_INDCPA_SECRETKEYBYTES;
extern size_t MLKEM_PUBLICKEYBYTES;
extern size_t MLKEM_SECRETKEYBYTES;
extern size_t MLKEM_CIPHERTEXTBYTES;
extern size_t MLKEM_INDCPA_BYTES;

// 모드에 따라 전역 변수 설정
void mlkem_set_mode(int mode);

#endif // MODE_CONFIG_H