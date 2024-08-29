export BASE_DIR=$(pwd)
echo $BASE_DIR
cd ./datasets/synthetic/src/mbedtls-v2.28.8/ && make && make run
cd ./datasets/synthetic/src/openssl-v1.1.1f/ && make && make run
cd ./datasets/synthetic/src/openssl-v3.3.1/ && make && make run
cd ./datasets/synthetic/src/wolfssl-v5.7.2-stable/ && make && make run
cd ./datasets/synthetic/ && ./copy.sh
