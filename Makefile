CC=/opt/homebrew/Cellar/gcc/12.2.0/bin/g++-12
CFLAGS=-std=c++11 -O3 -pthread -march=armv8-a+simd+crypto+crc
INCLUDE_PATH=-I. -I../ -I../Utils/secp256k1_lib -I/usr/local/include

SECP256K1_LIB=/usr/local/lib/libsecp256k1.a
NTL_LIB=/usr/local/lib/libntl.a
ZEROMQ_LIB=-L/opt/homebrew/Cellar/zeromq/4.3.4/lib 
GMP_LIB=-L/opt/homebrew/Cellar/gmp/6.2.1_1/lib 
OPENSSL_LIB=-L/opt/homebrew/opt/openssl/lib 

DEPS=$(ZEROMQ_LIB) $(GMP_LIB) $(OPENSSL_LIB) $(SECP256K1_LIB) $(NTL_LIB)
LIBS=-lzmq -lgmp -lm -lcrypto

all:
	cd Server; $(CC) $(CFLAGS) $(INCLUDE_PATH) *.cpp -o Server $(DEPS) $(LIBS)
	cd Client; $(CC) $(CFLAGS) $(INCLUDE_PATH) *.cpp -o Client $(DEPS) $(LIBS)

clean:
	cd Server; rm -f Server
	cd Client; rm -f Client

