BASE_DIR ?= /home/oak/Git/PQDetector/pqscan
LDFLAGS := -lcrypto

BIN_DIR = $(BASE_DIR)/datasets/synthetic/src/openssl-v1.1.1f/bin

all: direct-dep indirect-dep

indirect-dep: libqedtest.o
	gcc -shared -o $(BIN_DIR)/libqedtest.so $(BIN_DIR)/libqedtest.o $(LDFLAGS)
	gcc -o $(BIN_DIR)/openssl1.1-dh-indirect openssl1.1-dh-indirect.c -L$(BIN_DIR) -lqedtest -Wl,-rpath=$(BIN_DIR)
	gcc -o $(BIN_DIR)/openssl1.1-aes-indirect openssl1.1-aes-indirect.c -L$(BIN_DIR) -lqedtest -Wl,-rpath=$(BIN_DIR)
	gcc -o $(BIN_DIR)/openssl1.1-rsa-indirect openssl1.1-rsa-indirect.c -L$(BIN_DIR) -lqedtest -Wl,-rpath=$(BIN_DIR)
	gcc -o $(BIN_DIR)/openssl1.1-ecdsa-indirect openssl1.1-ecdsa-indirect.c -L$(BIN_DIR) -lqedtest -Wl,-rpath=$(BIN_DIR)
	gcc -o $(BIN_DIR)/openssl1.1-sha512-indirect openssl1.1-sha512-indirect.c -L$(BIN_DIR) -lqedtest -Wl,-rpath=$(BIN_DIR)


libqedtest.o: libqedtest.c
	gcc -c -fPIC libqedtest.c -o $(BIN_DIR)/libqedtest.o


direct-dep:
	gcc -o $(BIN_DIR)/openssl1.1-ecdsa openssl1.1-ecdsa.c $(LDFLAGS)
	gcc -o $(BIN_DIR)/openssl1.1-rsa openssl1.1-rsa.c $(LDFLAGS)
	gcc -o $(BIN_DIR)/openssl1.1-dh openssl1.1-dh.c $(LDFLAGS)
	gcc -o $(BIN_DIR)/openssl1.1-aes openssl1.1-aes.c $(LDFLAGS)
	gcc -o $(BIN_DIR)/openssl1.1-sha512 openssl1.1-sha512.c $(LDFLAGS)

run:
	$(BIN_DIR)/openssl1.1-ecdsa && $(BIN_DIR)/openssl1.1-rsa && $(BIN_DIR)/openssl1.1-dh && $(BIN_DIR)/openssl1.1-aes && $(BIN_DIR)/openssl1.1-sha512 && \
	$(BIN_DIR)/openssl1.1-ecdsa-indirect && $(BIN_DIR)/openssl1.1-rsa-indirect && $(BIN_DIR)/openssl1.1-dh-indirect && $(BIN_DIR)/openssl1.1-aes-indirect && $(BIN_DIR)/openssl1.1-sha512-indirect

clean:
	rm $(BIN_DIR)/*
