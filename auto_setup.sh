#!/bin/bash

# Update system 
sudo apt-get update

# Install building tools
sudo apt-get install -y build-essential

# Install python3 
sudo apt-get install -y python3

# Install Golang
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz --no-check-certificate
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Install ZeroMQ
sudo apt-get install -y libzmq3-dev

# Install libssl, libtool, m4, etc.
sudo apt-get install -y autogen automake ca-certificates cmake git libboost-dev libboost-thread-dev libsodium-dev libssl-dev libtool m4 texinfo yasm

# Install GMP
# sudo apt purge --remove libntl-dev libgmp-dev libgmp3-dev
wget https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz --no-check-certificate
tar -xf gmp-6.3.0.tar.xz 
cd gmp-6.3.0/
./configure
make -j 8
sudo make install 
cd .. 
sudo ldconfig

# Install NTL
wget https://libntl.org/ntl-11.5.1.tar.gz --no-check-certificate
tar -zxvf ntl-11.5.1.tar.gz
cd ntl-11.5.1/src
./configure GMP_PREFIX=/usr/local/lib
make -j 8
# make check
sudo make install
cd ../..

# Install gnark-crypto
wget https://github.com/Consensys/gnark-crypto/archive/refs/tags/v0.6.0.tar.gz --no-check-certificate
tar -zxvf v0.6.0.tar.gz
cp porla/main.go gnark-crypto-0.6.0/
cd gnark-crypto-0.6.0/
go build -buildmode=c-shared -o libmultiexp.so main.go
sudo cp libmultiexp.so /usr/lib
cd ..

# Build and install libsecp256k1
git clone https://github.com/bitcoin-core/secp256k1
cd secp256k1
git checkout 423b6d19d373f1224fd671a982584d7e7900bc93
./autogen.sh
./configure
make -j 8
sudo make install
cd ..

# Build porla source code
cd porla
make clean 
make -j 8
