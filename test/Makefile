CC = gcc
CFLAGS = -I../include -I../src/kem
SRC_DIR = ../src/kem
TEST_DIR = .

# 소스 파일 목록
KEM_SRCS = $(SRC_DIR)/kem.c \
           $(SRC_DIR)/poly.c \
           $(SRC_DIR)/polyvec.c \
           $(SRC_DIR)/ntt.c \
           $(SRC_DIR)/verify.c \
           $(SRC_DIR)/symmetric-shake.c \
           $(SRC_DIR)/reduce.c \
           $(SRC_DIR)/cbd.c \
           $(SRC_DIR)/indcpa.c \
           $(SRC_DIR)/get_func.c

TEST_SRCS = $(TEST_DIR)/ml-kem_test.c

# 오브젝트 파일 목록
KEM_OBJS = $(KEM_SRCS:.c=.o)
TEST_OBJS = $(TEST_SRCS:.c=.o)

# 최종 실행 파일
TARGET = ml-kem_test

all: $(TARGET)

$(TARGET): $(KEM_OBJS) $(TEST_OBJS)
	$(CC) -o $@ $^

# KEM 소스 파일 컴파일 규칙
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# 테스트 소스 파일 컴파일 규칙
$(TEST_DIR)/%.o: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(KEM_OBJS) $(TEST_OBJS) $(TARGET)

.PHONY: all clean