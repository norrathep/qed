BASE_DIR ?= /home/oak/Git/PQDetector/pqscan

LIB_DIR := $(BASE_DIR)/wolfssl-5.7.2-stable/src/.libs/
INCLUDE_DIR := $(BASE_DIR)/wolfssl-5.7.2-stable/IDE/PlatformIO/examples/wolfssl_benchmark/include/
LDFLAGS := -I$(INCLUDE_DIR) -L$(LIB_DIR) -Wl,-rpath=$(LIB_DIR) -lwolfssl
BIN_DIR = $(BASE_DIR)/datasets/synthetic/src/wolfssl-v5.7.2-stable/bin

all: direct-dep indirect-dep

indirect-dep: libqedtest.o
	gcc -shared -o $(BIN_DIR)/libqedtest.so $(BIN_DIR)/libqedtest.o $(LDFLAGS)
	gcc -o $(BIN_DIR)/wolfssl-dh-indirect wolfssl-dh-indirect.c -L$(BIN_DIR)/ -lqedtest -Wl,-rpath=$(BIN_DIR)/
	gcc -o $(BIN_DIR)/wolfssl-aes-indirect wolfssl-aes-indirect.c -L$(BIN_DIR)/ -lqedtest -Wl,-rpath=$(BIN_DIR)/
	gcc -o $(BIN_DIR)/wolfssl-rsa-indirect wolfssl-rsa-indirect.c -L$(BIN_DIR)/ -lqedtest -Wl,-rpath=$(BIN_DIR)/
	gcc -o $(BIN_DIR)/wolfssl-ecdsa-indirect wolfssl-ecdsa-indirect.c -L$(BIN_DIR)/ -lqedtest -Wl,-rpath=$(BIN_DIR)/
	gcc -o $(BIN_DIR)/wolfssl-sha512-indirect wolfssl-sha512-indirect.c -L$(BIN_DIR)/ -lqedtest -Wl,-rpath=$(BIN_DIR)/


libqedtest.o: libqedtest.c
	gcc -c -fPIC libqedtest.c -o $(BIN_DIR)/libqedtest.o


direct-dep:
	gcc -o $(BIN_DIR)/wolfssl-ecdsa wolfssl-ecdsa.c $(LDFLAGS)
	gcc -o $(BIN_DIR)/wolfssl-rsa wolfssl-rsa.c $(LDFLAGS)
	gcc -o $(BIN_DIR)/wolfssl-dh wolfssl-dh.c $(LDFLAGS)
	gcc -o $(BIN_DIR)/wolfssl-aes wolfssl-aes.c $(LDFLAGS)
	gcc -o $(BIN_DIR)/wolfssl-sha512 wolfssl-sha512.c $(LDFLAGS)

run:
	$(BIN_DIR)/wolfssl-sha512 $(BIN_DIR)/wolfssl-sha512 && $(BIN_DIR)/wolfssl-ecdsa && $(BIN_DIR)/wolfssl-dh \
	&& $(BIN_DIR)/wolfssl-rsa && $(BIN_DIR)/wolfssl-aes -i $(BIN_DIR)/wolfssl-aes -o $(BIN_DIR)/out -e 128 -d 128 \
	&& $(BIN_DIR)/wolfssl-sha512-indirect $(BIN_DIR)/wolfssl-sha512-indirect && $(BIN_DIR)/wolfssl-ecdsa-indirect \
	&& $(BIN_DIR)/wolfssl-dh-indirect && $(BIN_DIR)/wolfssl-rsa-indirect \
	&& $(BIN_DIR)/wolfssl-aes-indirect -i $(BIN_DIR)/wolfssl-aes-indirect -o $(BIN_DIR)/out -e 128 -d 128

clean:
	rm $(BIN_DIR)/*
