CC ?= gcc
CFLAGS ?= -O3 -march=native -fomit-frame-pointer -Wall -Wextra -std=c11
CFLAGS += -Iinclude -IPQClean-master/common
LDFLAGS ?=
WSIDH_PROFILE ?= 0

WITH_AVX2 ?= 0

KYBER_IMPL_DIR := clean

ifeq ($(WITH_AVX2),1)
  KYBER_IMPL_DIR := avx2
  CFLAGS += -DWSIDH_USE_AVX2 -mavx2 -mbmi2 -mpopcnt
endif

KYBER_DIR := third_party/PQClean/crypto_kem/kyber512/$(KYBER_IMPL_DIR)
KYBER_SRCS := $(wildcard $(KYBER_DIR)/*.c)
KYBER_S_SRCS := $(wildcard $(KYBER_DIR)/*.S)
KYBER_OBJS := $(KYBER_SRCS:.c=.o) $(KYBER_S_SRCS:.S=.o)

CFLAGS += -DWSIDH_PARAM_SET=WSIDH_PARAM_WS512 -DWSIDH_ENABLE_KYBER
CFLAGS += -I$(KYBER_DIR)

ifeq ($(WITH_AVX2),1)
  CFLAGS += -IPQClean-master/common/keccak4x
  KECCAK4X_OBJ := PQClean-master/common/keccak4x/KeccakP-1600-times4-SIMD256.o
  AVX2_OBJS := src/wsidh_avx2_ntt.o
else
  KECCAK4X_OBJ :=
  AVX2_OBJS :=
endif

ifeq ($(WSIDH_PROFILE),1)
  CFLAGS += -DWSIDH_ENABLE_PROFILE
endif

BUILD_FLAGS := $(CFLAGS)
CFLAGS += -DBUILD_FLAGS="\"$(BUILD_FLAGS)\""

COMMON_SRCS = src/params_256.c \
              src/poly.c \
              src/ntt.c \
              src/sha3.c \
              src/wsidh_kem.c \
              src/wsidh_params.c \
              src/wsidh_profiler.c \
              src/kyber_wrapper.c
COMMON_OBJS = $(COMMON_SRCS:.c=.o) \
              PQClean-master/common/fips202.o \
              PQClean-master/common/randombytes.o \
              $(KYBER_OBJS) \
              $(AVX2_OBJS) \
              $(KECCAK4X_OBJ)

TEST_OBJS = test/test_wsidh.o
BENCH_OBJS = test/bench_wsidh.o
BENCH_COMPARE_OBJS = test/bench_compare.o
BENCH_COMPARE_KYBER_OBJS = test/bench_compare_kyber_only.o
EXTRA_TEST_OBJS = test/test_ntt_roundtrip.o test/test_poly_mul.o test/test_kyber.o

BIN = wsidh_test wsidh_bench kyber512_bench bench_compare ntt_roundtrip_test \
      poly_mul_test kyber_test

.PHONY: all clean bench_all tests

all: wsidh_test wsidh_bench bench_compare

wsidh_test: $(COMMON_OBJS) $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

wsidh_bench: $(COMMON_OBJS) $(BENCH_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

kyber512_bench: $(COMMON_OBJS) $(BENCH_COMPARE_KYBER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

bench_compare: $(COMMON_OBJS) $(BENCH_COMPARE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

ntt_roundtrip_test: $(COMMON_OBJS) test/test_ntt_roundtrip.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

poly_mul_test: $(COMMON_OBJS) test/test_poly_mul.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

kyber_test: $(COMMON_OBJS) test/test_kyber.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

bench_all: bench_compare
	./bench_compare

tests: wsidh_test kyber_test ntt_roundtrip_test poly_mul_test
	./wsidh_test
	./kyber_test
	./ntt_roundtrip_test
	./poly_mul_test

test/bench_wsidh.o: test/bench_wsidh.c
	$(CC) $(CFLAGS) -c $< -o $@

test/bench_compare.o: test/bench_compare.c
	$(CC) $(CFLAGS) -c $< -o $@

test/bench_compare_kyber_only.o: test/bench_compare.c
	$(CC) $(CFLAGS) -DBENCH_KYBER_ONLY -c $< -o $@

test/test_wsidh.o: test/test_wsidh.c
	$(CC) $(CFLAGS) -c $< -o $@

test/test_ntt_roundtrip.o: test/test_ntt_roundtrip.c
	$(CC) $(CFLAGS) -c $< -o $@

test/test_poly_mul.o: test/test_poly_mul.c
	$(CC) $(CFLAGS) -c $< -o $@

test/test_kyber.o: test/test_kyber.c
	$(CC) $(CFLAGS) -c $< -o $@

PQClean-master/common/fips202.o: PQClean-master/common/fips202.c
	$(CC) $(CFLAGS) -c $< -o $@

PQClean-master/common/randombytes.o: PQClean-master/common/randombytes.c
	$(CC) $(CFLAGS) -c $< -o $@

ifeq ($(WITH_AVX2),1)
PQClean-master/common/keccak4x/KeccakP-1600-times4-SIMD256.o: PQClean-master/common/keccak4x/KeccakP-1600-times4-SIMD256.c
	$(CC) $(CFLAGS) -c $< -o $@
endif

$(KYBER_DIR)/%.o: $(KYBER_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(KYBER_DIR)/%.o: $(KYBER_DIR)/%.S
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(COMMON_OBJS) $(TEST_OBJS) $(BENCH_OBJS) \
	      $(BENCH_COMPARE_OBJS) $(BENCH_COMPARE_KYBER_OBJS) \
	      $(EXTRA_TEST_OBJS) $(BIN)
ifeq ($(WSIDH_PROFILE),1)
  CFLAGS += -DWSIDH_ENABLE_PROFILE
endif
