CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c11 -Iinclude -IPQClean-master/common
LDFLAGS =

override WITH_KYBER := 1
WITH_AVX2 ?= 0
WSIDH_PROFILE ?= 0
WSIDH_VARIANT ?= wsidh512

KYBER_IMPL_DIR := clean
KYBER_API_SUFFIX := CLEAN

ifeq ($(WSIDH_VARIANT),wsidh512)
  WSIDH_PARAM_DEFINE = -DWSIDH_PARAM_SET=WSIDH_PARAM_WS512
else ifeq ($(WSIDH_VARIANT),wsidh768)
  WSIDH_PARAM_DEFINE = -DWSIDH_PARAM_SET=WSIDH_PARAM_WS768
else ifeq ($(WSIDH_VARIANT),wsidh1024)
  WSIDH_PARAM_DEFINE = -DWSIDH_PARAM_SET=WSIDH_PARAM_WS1024
else
  $(error Unknown WSIDH_VARIANT $(WSIDH_VARIANT))
endif

CFLAGS += $(WSIDH_PARAM_DEFINE)

ifeq ($(WSIDH_PROFILE),1)
  CFLAGS += -DWSIDH_ENABLE_PROFILE
endif

KYBER_LIBS ?=
KYBER_CPPFLAGS :=
ifeq ($(WITH_AVX2),1)
  KYBER_IMPL_DIR := avx2
  KYBER_API_SUFFIX := AVX2
endif

KYBER512_DIR ?= third_party/PQClean/crypto_kem/kyber512/$(KYBER_IMPL_DIR)
KYBER768_DIR ?= third_party/PQClean/crypto_kem/kyber768/$(KYBER_IMPL_DIR)
KYBER1024_DIR ?= third_party/PQClean/crypto_kem/kyber1024/$(KYBER_IMPL_DIR)

KYBER_DIRS :=
KYBER_C_SRCS :=
KYBER_S_SRCS :=

ifeq ($(WITH_KYBER),1)
  ifneq ($(wildcard $(KYBER512_DIR)),)
    KYBER_DIRS += $(KYBER512_DIR)
  else
    $(warning Kyber512 directory missing: $(KYBER512_DIR))
  endif
  ifneq ($(wildcard $(KYBER768_DIR)),)
    KYBER_DIRS += $(KYBER768_DIR)
  else
    $(warning Kyber768 directory missing: $(KYBER768_DIR))
  endif
  ifneq ($(wildcard $(KYBER1024_DIR)),)
    KYBER_DIRS += $(KYBER1024_DIR)
  else
    $(warning Kyber1024 directory missing: $(KYBER1024_DIR))
  endif
  ifneq ($(KYBER_DIRS),)
    KYBER_CPPFLAGS += -DWSIDH_ENABLE_KYBER
    CFLAGS += $(addprefix -I,$(KYBER_DIRS)) -IPQClean-master/common
    KYBER_C_SRCS := $(foreach dir,$(KYBER_DIRS),$(wildcard $(dir)/*.c))
    KYBER_S_SRCS := $(foreach dir,$(KYBER_DIRS),$(wildcard $(dir)/*.S))
  else
    $(warning WITH_KYBER=1 but no Kyber sources detected; using WSIDH-only path.)
  endif
endif

CFLAGS += $(KYBER_CPPFLAGS)

AVX2_DIR :=
AVX2_SRCS :=
AVX2_OBJS :=
KECCAK4X_OBJ :=
WSIDH_AVX2_INCLUDE_DIR := PQClean-master/crypto_kem/ml-kem-512/avx2
WSIDH_AVX2_BASE_REL := ../PQClean-master/crypto_kem/ml-kem-512/avx2

ifeq ($(WITH_AVX2),1)
  ifeq ($(WITH_KYBER),1)
    WSIDH_AVX2_INCLUDE_DIR := third_party/PQClean/crypto_kem/kyber512/avx2
    WSIDH_AVX2_BASE_REL := ../third_party/PQClean/crypto_kem/kyber512/avx2
    AVX2_SRCS :=
  else
    AVX2_SRCS := $(WSIDH_AVX2_INCLUDE_DIR)/consts.c \
                 $(WSIDH_AVX2_INCLUDE_DIR)/basemul.S $(WSIDH_AVX2_INCLUDE_DIR)/fq.S \
                 $(WSIDH_AVX2_INCLUDE_DIR)/invntt.S $(WSIDH_AVX2_INCLUDE_DIR)/ntt.S \
                 $(WSIDH_AVX2_INCLUDE_DIR)/shuffle.S $(WSIDH_AVX2_INCLUDE_DIR)/fips202x4.c
  endif
  AVX2_DIR := $(WSIDH_AVX2_INCLUDE_DIR)
  CFLAGS += -DWSIDH_USE_AVX2 -I$(WSIDH_AVX2_INCLUDE_DIR) -IPQClean-master/common/keccak4x -DWSIDH_AVX2_BASE=$(WSIDH_AVX2_BASE_REL) -mavx2 -mbmi2 -mpopcnt
  AVX2_OBJS := $(patsubst %.c,%.o,$(patsubst %.S,%.o,$(AVX2_SRCS))) src/wsidh_avx2.o
  KECCAK4X_OBJ := PQClean-master/common/keccak4x/KeccakP-1600-times4-SIMD256.o
endif

KYBER_C_OBJS := $(patsubst %.c,%.o,$(KYBER_C_SRCS))
KYBER_S_OBJS := $(patsubst %.S,%.o,$(KYBER_S_SRCS))
KYBER_PQC_OBJS := $(KYBER_C_OBJS) $(KYBER_S_OBJS)

COMMON_OBJS = src/params_256.o src/poly.o src/ntt.o src/sha3.o src/wsidh_kem.o src/wsidh_params.o src/wsidh_profiler.o PQClean-master/common/fips202.o PQClean-master/common/randombytes.o $(KYBER_PQC_OBJS) $(AVX2_OBJS)
COMMON_OBJS += $(KECCAK4X_OBJ)
TEST_OBJS   = test/test_wsidh.o
BENCH_OBJS  = test/bench_wsidh.o
KYBER_OBJS  = test/bench_wsidh_kyber.o

BIN = wsidh_test wsidh_bench wsidh_vs_kyber

.PHONY: all clean

all: wsidh_test wsidh_bench

wsidh_test: $(COMMON_OBJS) $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(KYBER_LIBS) $(LDFLAGS)

wsidh_bench: $(COMMON_OBJS) $(BENCH_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(KYBER_LIBS) $(LDFLAGS)

test/bench_wsidh.o: test/bench_wsidh.c
	$(CC) $(CFLAGS) -c $< -o $@

$(KYBER_C_OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(KYBER_S_OBJS): %.o: %.S
	$(CC) $(CFLAGS) -c $< -o $@

PQClean-master/common/fips202.o: PQClean-master/common/fips202.c
	$(CC) $(CFLAGS) -c $< -o $@

PQClean-master/common/randombytes.o: PQClean-master/common/randombytes.c
	$(CC) $(CFLAGS) -c $< -o $@

ifeq ($(WITH_AVX2),1)
PQClean-master/common/keccak4x/KeccakP-1600-times4-SIMD256.o: PQClean-master/common/keccak4x/KeccakP-1600-times4-SIMD256.c
	$(CC) $(CFLAGS) -c $< -o $@

$(AVX2_DIR)/%.o: $(AVX2_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(AVX2_DIR)/%.o: $(AVX2_DIR)/%.S
	$(CC) $(CFLAGS) -c $< -o $@
endif

test/bench_wsidh_kyber.o: test/bench_wsidh.c
	$(CC) $(CFLAGS) $(KYBER_CPPFLAGS) -c $< -o $@

wsidh_vs_kyber: $(COMMON_OBJS) $(KYBER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(KYBER_LIBS) $(LDFLAGS)

clean:
	rm -f $(COMMON_OBJS) $(TEST_OBJS) $(BENCH_OBJS) $(KYBER_OBJS) $(BIN)
