BASE_DIR ?= /home/oak/Git/PQDetector/pqscan
LIB_DIR := $(BASE_DIR)/mbedtls-2.28.8/build/library
INCLUDE_DIR := $(BASE_DIR)/mbedtls-2.28.8/build/include/
LDFLAGS := -I$(INCLUDE_DIR) -L$(LIB_DIR) -Wl,-rpath=$(LIB_DIR) -lmbedcrypto
BIN_DIR = $(BASE_DIR)/datasets/synthetic/src/mbedtls-v2.28.8/bin

all: direct-dep indirect-dep

indirect-dep: libqedtest.o
	gcc -shared -o $(BIN_DIR)/libqedtest.so $(BIN_DIR)/libqedtest.o $(LDFLAGS)
	gcc -o $(BIN_DIR)/mbedtls-rsa-indirect mbedtls-rsa-indirect.c -L$(BIN_DIR)/ -lqedtest -Wl,-rpath=$(BIN_DIR)/ -I$(INCLUDE_DIR)
	gcc -o $(BIN_DIR)/mbedtls-ecdsa-indirect mbedtls-ecdsa-indirect.c -L$(BIN_DIR)/ -lqedtest -Wl,-rpath=$(BIN_DIR)/ -I$(INCLUDE_DIR)
	gcc -o $(BIN_DIR)/mbedtls-dh-indirect mbedtls-dh-indirect.c -L$(BIN_DIR)/ -lqedtest -Wl,-rpath=$(BIN_DIR)/ -I$(INCLUDE_DIR)
	gcc -o $(BIN_DIR)/mbedtls-aes-indirect mbedtls-aes-indirect.c -L$(BIN_DIR)/ -lqedtest -Wl,-rpath=$(BIN_DIR)/ -I$(INCLUDE_DIR)
	gcc -o $(BIN_DIR)/mbedtls-sha512-indirect mbedtls-sha512-indirect.c -L$(BIN_DIR)/ -lqedtest -Wl,-rpath=$(BIN_DIR)/ -I$(INCLUDE_DIR)


libqedtest.o: libqedtest.c
	gcc -c -fPIC libqedtest.c -o $(BIN_DIR)/libqedtest.o -I$(INCLUDE_DIR)


direct-dep:
	gcc -o $(BIN_DIR)/mbedtls-rsa mbedtls-rsa.c $(LDFLAGS)
	gcc -o $(BIN_DIR)/mbedtls-ecdsa mbedtls-ecdsa.c $(LDFLAGS)
	gcc -o $(BIN_DIR)/mbedtls-dh mbedtls-dh.c $(LDFLAGS)
	gcc -o $(BIN_DIR)/mbedtls-aes mbedtls-aes.c $(LDFLAGS)
	gcc -o $(BIN_DIR)/mbedtls-sha512 mbedtls-sha512.c $(LDFLAGS)

run:
	$(BIN_DIR)/mbedtls-sha512 SHA512 test.txt && $(BIN_DIR)/mbedtls-ecdsa && $(BIN_DIR)/mbedtls-dh \
	&& $(BIN_DIR)/mbedtls-rsa && $(BIN_DIR)/mbedtls-aes 0 test.txt $(BIN_DIR)/test.out AES-128-CBC SHA1 hex:E76B2413958B00E193 \
	&& $(BIN_DIR)/mbedtls-sha512-indirect SHA512 test.txt && $(BIN_DIR)/mbedtls-ecdsa-indirect && $(BIN_DIR)/mbedtls-dh-indirect \
	&& $(BIN_DIR)/mbedtls-rsa-indirect && $(BIN_DIR)/mbedtls-aes-indirect 0 test.txt $(BIN_DIR)/test.out AES-128-CBC SHA1 hex:E76B2413958B00E193 \

clean:
	rm $(BIN_DIR)/*
