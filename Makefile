# 컴파일러 설정
CC = gcc
AR = ar
CFLAGS = -O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -std=c99
INCLUDES = -I.

# 디렉토리 설정
COMMON_DIR = common
ML_KEM_512_DIR = ml-kem-512/clean
ML_KEM_768_DIR = ml-kem-768/clean
ML_KEM_1024_DIR = ml-kem-1024/clean
ML_DSA_44_DIR = ml-dsa-44/clean
ML_DSA_65_DIR = ml-dsa-65/clean
ML_DSA_87_DIR = ml-dsa-87/clean
SPHINCS_SHA2_128f_DIR = sphincs-sha2-128f-simple/clean
SPHINCS_SHA2_128s_DIR = sphincs-sha2-128s-simple/clean
SPHINCS_SHA2_192f_DIR = sphincs-sha2-192f-simple/clean
SPHINCS_SHA2_192s_DIR = sphincs-sha2-192s-simple/clean



# 라이브러리 파일
ML_KEM_512_LIB = $(ML_KEM_512_DIR)/libml-kem-512_clean.a
ML_KEM_768_LIB = $(ML_KEM_768_DIR)/libml-kem-768_clean.a
ML_KEM_1024_LIB = $(ML_KEM_1024_DIR)/libml-kem-1024_clean.a
ML_DSA_44_LIB = $(ML_DSA_44_DIR)/libml-dsa-44_clean.a
ML_DSA_65_LIB = $(ML_DSA_65_DIR)/libml-dsa-65_clean.a
ML_DSA_87_LIB = $(ML_DSA_87_DIR)/libml-dsa-87_clean.a
SPHINCS_SHA2_128f_LIB = $(SPHINCS_SHA2_128f_DIR)/libsphincs-sha2-128f-simple_clean.a
SPHINCS_SHA2_128s_LIB = $(SPHINCS_SHA2_128s_DIR)/libsphincs-sha2-128s-simple_clean.a
SPHINCS_SHA2_192f_LIB = $(SPHINCS_SHA2_192f_DIR)/libsphincs-sha2-192f-simple_clean.a
SPHINCS_SHA2_192s_LIB = $(SPHINCS_SHA2_192s_DIR)/libsphincs-sha2-192s-simple_clean.a

# 공통 오브젝트 파일
COMMON_OBJS = $(COMMON_DIR)/fips202.o $(COMMON_DIR)/randombytes.o $(COMMON_DIR)/sha2.o

# 메인 오브젝트 파일
MAIN_OBJS = ml_crypto.o

# 테스트 프로그램
TEST_PROG = test_program

all: $(TEST_PROG)

# ML-KEM-512 라이브러리 빌드
$(ML_KEM_512_LIB):
	$(MAKE) -C $(ML_KEM_512_DIR)

# ML-KEM-768 라이브러리 빌드
$(ML_KEM_768_LIB):
	$(MAKE) -C $(ML_KEM_768_DIR)

# ML-KEM-1024 라이브러리 빌드
$(ML_KEM_1024_LIB):
	$(MAKE) -C $(ML_KEM_1024_DIR)

# ML-DSA 44 라이브러리 빌드
$(ML_DSA_44_LIB):
	$(MAKE) -C $(ML_DSA_44_DIR)
# ML-DSA 65 라이브러리 빌드
$(ML_DSA_65_LIB):
	$(MAKE) -C $(ML_DSA_65_DIR)
# ML-DSA 87 라이브러리 빌드
$(ML_DSA_87_LIB):
	$(MAKE) -C $(ML_DSA_87_DIR)

# SPHINCS-SHA2-128(fast)라이브러리 빌드
$(SPHINCS_SHA2_128f_LIB):
	$(MAKE) -C $(SPHINCS_SHA2_128f_DIR)
# SPHINCS-SHA2-128(small)라이브러리 빌드
$(SPHINCS_SHA2_128s_LIB):
	$(MAKE) -C $(SPHINCS_SHA2_128s_DIR)
# SPHINCS+ SHA2-192(fast)라이브러리 빌드
$(SPHINCS_SHA2_192f_LIB):
	$(MAKE) -C $(SPHINCS_SHA2_192f_DIR)
# SPHINCS+ SHA2-192(small)라이브러리 빌드
$(SPHINCS_SHA2_192s_LIB):
	$(MAKE) -C $(SPHINCS_SHA2_192s_DIR)

# 공통 오브젝트 파일 빌드
$(COMMON_DIR)/fips202.o: $(COMMON_DIR)/fips202.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(COMMON_DIR)/randombytes.o: $(COMMON_DIR)/randombytes.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(COMMON_DIR)/sha2.o: $(COMMON_DIR)/sha2.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# 메인 오브젝트 파일 빌드
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# 테스트 프로그램 빌드
$(TEST_PROG): $(COMMON_OBJS) $(MAIN_OBJS) $(ML_KEM_512_LIB) $(ML_KEM_768_LIB) $(ML_KEM_1024_LIB) \
              $(ML_DSA_44_LIB) $(ML_DSA_65_LIB) $(ML_DSA_87_LIB)
	$(CC) $(CFLAGS) -o $@ test/test.c $(MAIN_OBJS) $(COMMON_OBJS) \
		$(ML_KEM_512_LIB) \
		$(ML_KEM_768_LIB) \
		$(ML_KEM_1024_LIB) \
		$(ML_DSA_44_LIB) \
		$(ML_DSA_65_LIB) \
		$(ML_DSA_87_LIB) \
		$(SPHINCS_SHA2_128f_LIB) \
		$(SPHINCS_SHA2_128s_LIB) \
		$(SPHINCS_SHA2_192f_LIB) \
		$(SPHINCS_SHA2_192s_LIB) \
		$(INCLUDES)

clean:
	rm -f $(COMMON_OBJS) $(MAIN_OBJS) $(TEST_PROG)
	$(MAKE) -C $(ML_KEM_512_DIR) clean
	$(MAKE) -C $(ML_KEM_768_DIR) clean
	$(MAKE) -C $(ML_KEM_1024_DIR) clean
	$(MAKE) -C $(ML_DSA_44_DIR) clean
	$(MAKE) -C $(ML_DSA_65_DIR) clean
	$(MAKE) -C $(ML_DSA_87_DIR) clean
	$(MAKE) -C $(SPHINCS_SHA2_128f_DIR) clean
	$(MAKE) -C $(SPHINCS_SHA2_128s_DIR) clean
	$(MAKE) -C $(SPHINCS_SHA2_192f_DIR) clean
	$(MAKE) -C $(SPHINCS_SHA2_192s_DIR) clean


.PHONY: all clean