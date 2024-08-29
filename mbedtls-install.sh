wget https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v2.28.8.tar.gz
tar -xzf v2.28.8.tar.gz

cd mbedtls-2.28.8 && mkdir build && cd build && cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .. && make -j8
