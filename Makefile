CC = gcc
AR = ar
CFLAGS = -O3 -fPIC -Wall -Wextra -Wpedantic -std=c99
LDFLAGS = -shared

# 디렉토리 설정
INCLUDE_DIR = include
SRC_DIR = src
OBJ_DIR = obj
LIB_DIR = lib

# 헤더 파일 포함 경로
INCLUDES = -I$(INCLUDE_DIR) \
          -I$(SRC_DIR)/common \
          -I$(SRC_DIR)/kem/ml-kem-512/clean \
          -I$(SRC_DIR)/kem/ml-kem-768/clean \
          -I$(SRC_DIR)/kem/ml-kem-1024/clean \
          -I$(SRC_DIR)/sign/dilithium/ml-dsa-44/clean \
          -I$(SRC_DIR)/sign/dilithium/ml-dsa-65/clean \
          -I$(SRC_DIR)/sign/dilithium/ml-dsa-87/clean \
          -I$(SRC_DIR)/sign/sphincs+/sha2/sphincs-sha2-128f-simple/clean \
          -I$(SRC_DIR)/sign/sphincs+/sha2/sphincs-sha2-128s-simple/clean \
          -I$(SRC_DIR)/sign/sphincs+/sha2/sphincs-sha2-192f-simple/clean \
          -I$(SRC_DIR)/sign/sphincs+/sha2/sphincs-sha2-192s-simple/clean

CFLAGS += $(INCLUDES)

# 최종 라이브러리
SHARED_LIB = $(LIB_DIR)/libpqc.so

# KEM 소스 파일
KEM_COMMON_SRCS = $(wildcard $(SRC_DIR)/kem/*.c)
KEM_512_SRCS = $(wildcard $(SRC_DIR)/kem/ml-kem-512/clean/*.c)
KEM_768_SRCS = $(wildcard $(SRC_DIR)/kem/ml-kem-768/clean/*.c)
KEM_1024_SRCS = $(wildcard $(SRC_DIR)/kem/ml-kem-1024/clean/*.c)

# SIGN 소스 파일
SIGN_COMMON_SRCS = $(wildcard $(SRC_DIR)/sign/*.c)
DSA_44_SRCS = $(wildcard $(SRC_DIR)/sign/dilithium/ml-dsa-44/clean/*.c)
DSA_65_SRCS = $(wildcard $(SRC_DIR)/sign/dilithium/ml-dsa-65/clean/*.c)
DSA_87_SRCS = $(wildcard $(SRC_DIR)/sign/dilithium/ml-dsa-87/clean/*.c)
SPHINCS_SRCS = $(wildcard $(SRC_DIR)/sign/sphincs+/sha2/sphincs-sha2-128f-simple/clean/*.c)
SPHINCS_SRCS += $(wildcard $(SRC_DIR)/sign/sphincs+/sha2/sphincs-sha2-128s-simple/clean/*.c)
SPHINCS_SRCS += $(wildcard $(SRC_DIR)/sign/sphincs+/sha2/sphincs-sha2-192f-simple/clean/*.c)
SPHINCS_SRCS += $(wildcard $(SRC_DIR)/sign/sphincs+/sha2/sphincs-sha2-192s-simple/clean/*.c)

# 공통 소스 파일
COMMON_SRCS = $(wildcard $(SRC_DIR)/common/*.c)

# 모든 소스 파일
ALL_SRCS = $(KEM_COMMON_SRCS) \
           $(KEM_512_SRCS) \
           $(KEM_768_SRCS) \
           $(KEM_1024_SRCS) \
           $(SIGN_COMMON_SRCS) \
           $(DSA_44_SRCS) \
           $(DSA_65_SRCS) \
           $(DSA_87_SRCS) \
           $(SPHINCS_SRCS) \
           $(COMMON_SRCS)

# 오브젝트 파일
ALL_OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(ALL_SRCS))

# 기본 타겟
all: directories $(SHARED_LIB)

# 디렉토리 생성
directories:
	@mkdir -p $(LIB_DIR)
	@mkdir -p $(OBJ_DIR)/kem/ml-kem-512/clean
	@mkdir -p $(OBJ_DIR)/kem/ml-kem-768/clean
	@mkdir -p $(OBJ_DIR)/kem/ml-kem-1024/clean
	@mkdir -p $(OBJ_DIR)/sign/dilithium/ml-dsa-44/clean
	@mkdir -p $(OBJ_DIR)/sign/dilithium/ml-dsa-65/clean
	@mkdir -p $(OBJ_DIR)/sign/dilithium/ml-dsa-87/clean
	@mkdir -p $(OBJ_DIR)/sign/sphincs+/sha2/sphincs-sha2-128f-simple/clean
	@mkdir -p $(OBJ_DIR)/sign/sphincs+/sha2/sphincs-sha2-128s-simple/clean
	@mkdir -p $(OBJ_DIR)/sign/sphincs+/sha2/sphincs-sha2-192f-simple/clean
	@mkdir -p $(OBJ_DIR)/sign/sphincs+/sha2/sphincs-sha2-192s-simple/clean
	@mkdir -p $(OBJ_DIR)/common

# 공유 라이브러리 생성
$(SHARED_LIB): $(ALL_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

# 소스 파일 컴파일 규칙
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# 설치
install: all
	install -d $(PREFIX)/lib
	install -d $(PREFIX)/include
	install $(SHARED_LIB) $(PREFIX)/lib
	install $(INCLUDE_DIR)/pqc_*.h $(PREFIX)/include

# 테스트 빌드
test: $(SHARED_LIB)
	$(CC) $(CFLAGS) test/test_kem.c -Llib -lpqc -Wl,-rpath,$(PWD)/lib -o test/test_kem
	$(CC) $(CFLAGS) test/test_sign.c -Llib -lpqc -Wl,-rpath,$(PWD)/lib -o test/test_sign

# 정리
clean:
	rm -rf $(OBJ_DIR)
	rm -rf $(LIB_DIR)
	rm -f test/test_kem test/test_sign

.PHONY: all clean directories install test
