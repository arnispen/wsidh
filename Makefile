CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c11 -Iinclude -IPQClean-master/common -DWSIDH_ENABLE_PROFILE
LDFLAGS =

WITH_KYBER ?= 0
WITH_AVX2 ?= 0
WSIDH_VARIANT ?= wsidh512

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

KYBER_LIBS ?=
KYBER_CPPFLAGS :=
KYBER512_DIR ?= third_party/PQClean/crypto_kem/kyber512/clean
KYBER768_DIR ?= third_party/PQClean/crypto_kem/kyber768/clean
KYBER1024_DIR ?= third_party/PQClean/crypto_kem/kyber1024/clean

KYBER_DIRS :=
KYBER_SRCS :=

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
    KYBER_SRCS := $(foreach dir,$(KYBER_DIRS),$(wildcard $(dir)/*.c))
    KYBER_SRCS += $(wildcard PQClean-master/common/*.c)
  else
    $(warning WITH_KYBER=1 but no Kyber sources detected; using WSIDH-only path.)
  endif
endif

CFLAGS += $(KYBER_CPPFLAGS)

AVX2_DIR :=
AVX2_SRCS :=
AVX2_OBJS :=

ifeq ($(WITH_AVX2),1)
  AVX2_DIR := PQClean-master/crypto_kem/ml-kem-512/avx2
  CFLAGS += -DWSIDH_USE_AVX2 -I$(AVX2_DIR) -mavx2 -mbmi2 -mpopcnt
  AVX2_SRCS := $(AVX2_DIR)/consts.c \
               $(AVX2_DIR)/basemul.S $(AVX2_DIR)/fq.S \
               $(AVX2_DIR)/invntt.S $(AVX2_DIR)/ntt.S \
               $(AVX2_DIR)/shuffle.S
  AVX2_OBJS := $(patsubst %.c,%.o,$(patsubst %.S,%.o,$(AVX2_SRCS))) src/wsidh_avx2.o
endif

KYBER_PQC_OBJS := $(patsubst %.c,%.o,$(KYBER_SRCS))

COMMON_OBJS = src/poly.o src/ntt.o src/sha3.o src/wsidh_kem.o src/wsidh_params.o src/wsidh_profiler.o PQClean-master/common/fips202.o $(KYBER_PQC_OBJS) $(AVX2_OBJS)
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

$(KYBER_PQC_OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

PQClean-master/common/fips202.o: PQClean-master/common/fips202.c
	$(CC) $(CFLAGS) -c $< -o $@

ifeq ($(WITH_AVX2),1)
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
