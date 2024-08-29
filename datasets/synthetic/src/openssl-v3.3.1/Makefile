BASE_DIR ?= /home/oak/Git/PQDetector/pqscan
LIB_DIR := $(BASE_DIR)/openssl-3.3.1
INCLUDE_DIR := $(BASE_DIR)/openssl-3.3.1/include/
LDFLAGS := -I$(INCLUDE_DIR) -L$(LIB_DIR) -Wl,-rpath=$(LIB_DIR) -lcrypto -lssl
BIN_DIR = $(BASE_DIR)/datasets/synthetic/src/openssl-v3.3.1/bin

all: direct-dep indirect-dep

indirect-dep: libqedtest.o
	gcc -shared -o $(BIN_DIR)/libqedtest.so $(BIN_DIR)/libqedtest.o $(LDFLAGS)
	gcc -o $(BIN_DIR)/openssl3.3-rsa-indirect openssl3.3-rsa-indirect.c -L$(BIN_DIR)/ -lqedtest -Wl,-rpath=$(BIN_DIR)/ -I$(INCLUDE_DIR)
	gcc -o $(BIN_DIR)/openssl3.3-ecdsa-indirect openssl3.3-ecdsa-indirect.c -L$(BIN_DIR)/ -lqedtest -Wl,-rpath=$(BIN_DIR)/ -I$(INCLUDE_DIR)
	gcc -o $(BIN_DIR)/openssl3.3-dh-indirect openssl3.3-dh-indirect.c -L$(BIN_DIR)/ -lqedtest -Wl,-rpath=$(BIN_DIR)/ -I$(INCLUDE_DIR)
	gcc -o $(BIN_DIR)/openssl3.3-aes-indirect openssl3.3-aes-indirect.c -L$(BIN_DIR)/ -lqedtest -Wl,-rpath=$(BIN_DIR)/ -I$(INCLUDE_DIR)
	gcc -o $(BIN_DIR)/openssl3.3-sha512-indirect openssl3.3-sha512-indirect.c -L$(BIN_DIR)/ -lqedtest -Wl,-rpath=$(BIN_DIR)/ -I$(INCLUDE_DIR)


libqedtest.o: libqedtest.c
	gcc -c -fPIC libqedtest.c -o $(BIN_DIR)/libqedtest.o -I$(INCLUDE_DIR)


direct-dep:
	gcc -o $(BIN_DIR)/openssl3.3-rsa openssl3.3-rsa.c $(LDFLAGS)
	gcc -o $(BIN_DIR)/openssl3.3-ecdsa openssl3.3-ecdsa.c $(LDFLAGS)
	gcc -o $(BIN_DIR)/openssl3.3-dh openssl3.3-dh.c $(LDFLAGS)
	gcc -o $(BIN_DIR)/openssl3.3-aes openssl3.3-aes.c $(LDFLAGS)
	gcc -o $(BIN_DIR)/openssl3.3-sha512 openssl3.3-sha512.c $(LDFLAGS)

run:
	$(BIN_DIR)/openssl3.3-sha512 && $(BIN_DIR)/openssl3.3-ecdsa && $(BIN_DIR)/openssl3.3-dh && $(BIN_DIR)/openssl3.3-rsa && $(BIN_DIR)/openssl3.3-aes \
	&& $(BIN_DIR)/openssl3.3-aes-indirect $(BIN_DIR)/openssl3.3-sha512-indirect && $(BIN_DIR)/openssl3.3-ecdsa-indirect && $(BIN_DIR)/openssl3.3-dh-indirect && $(BIN_DIR)/openssl3.3-rsa-indirect

clean:
	rm $(BIN_DIR)/*