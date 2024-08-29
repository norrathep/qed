wget https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.7.2-stable.tar.gz
tar -xzf v5.7.2-stable.tar.gz

cd wolfssl-5.7.2-stable && ./autogen.sh && ./configure --enable-keygen --enable-pwdbased && make -j8 && sudo make install
