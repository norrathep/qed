wget https://www.openssl.org/source/openssl-3.3.1.tar.gz
tar -xzf openssl-3.3.1.tar.gz
cd ./openssl-3.3.1 && ./config && make -j8
sudo apt install openssl libssl1.1
