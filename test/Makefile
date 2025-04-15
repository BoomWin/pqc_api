CC = gcc
CFLAGS = -I../include -I../src/kem -I../common

# common 오브젝트 파일들 (이미 컴파일된 파일)
COMMON_OBJS = ../src/common/fips202.o ../src/common/randombytes.o ../src/common/sha2.o

# 소스 파일 목록
KEM_SRCS = ../src/kem/kem.c \
           ../src/kem/poly.c \
           ../src/kem/polyvec.c \
           ../src/kem/ntt.c \
           ../src/kem/verify.c \
           ../src/kem/symmetric-shake.c \
           ../src/kem/reduce.c \
           ../src/kem/cbd.c \
           ../src/kem/indcpa.c \
           ../src/kem/get_func.c

TEST_SRCS = ml-kem_test.c

# 오브젝트 파일 목록
KEM_OBJS = $(KEM_SRCS:.c=.o)
TEST_OBJS = $(TEST_SRCS:.c=.o)

# 최종 실행 파일
TARGET = ml-kem_test

all: $(TARGET)

$(TARGET): $(KEM_OBJS) $(TEST_OBJS) $(COMMON_OBJS)
	$(CC) -o $@ $^

# KEM 소스 파일 컴파일 규칙
../src/kem/%.o: ../src/kem/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# 테스트 소스 파일 컴파일 규칙
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(KEM_OBJS) $(TEST_OBJS) $(TARGET)

.PHONY: all clean