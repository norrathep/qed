# Minimal build to produce executables (they are not runnable...)
# If you want to build a fully functional set of tpm2 executables, follow:
# https://francislampayan.medium.com/how-to-setup-tpm-simulator-in-ubuntu-20-04-25ec673b88dc
sudo apt-get install lcov \
pandoc autoconf-archive liburiparser-dev \
libdbus-1-dev libglib2.0-dev dbus-x11 \
libssl-dev autoconf automake \
libtool pkg-config gcc \
libcurl4-gnutls-dev libgcrypt20-dev libcmocka-dev uthash-dev

# install json-c on top of the other dependencies we've installed from the previous step
sudo apt-get install libjson-c-dev

# download release 3.1.0 of tpm2-tss
wget https://github.com/tpm2-software/tpm2-tss/releases/download/3.1.0/tpm2-tss-3.1.0.tar.gz

# extract, configure and build
tar -xzvf tpm2-tss-3.1.0.tar.gz
cd tpm2-tss-3.1.0/ && ./configure && sudo make install -j8

# download from official release
wget https://github.com/tpm2-software/tpm2-tools/releases/download/4.3.2/tpm2-tools-4.3.2.tar.gz

# extract, configure, install
tar -xzvf tpm2-tools-4.3.2.tar.gz && cd tpm2-tools-4.3.2/ && ./configure &&sudo make install -j8

