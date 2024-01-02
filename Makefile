CC=g++
CFLAGS=-std=c++11 -O3 -pthread -march=native
INCLUDE_PATH=-I. -I../ -I../Utils/secp256k1_lib -I/usr/local/include

# Change the following paths of libraries if necessary
SECP256K1_LIB=/usr/local/lib/libsecp256k1.a
NTL_LIB=/usr/local/lib/libntl.a
ZEROMQ_LIB=-L/usr/local/lib
GMP_LIB=/usr/local/lib/libgmp.a
OPENSSL_LIB=-L/usr/local/lib

DEPS=$(ZEROMQ_LIB) $(GMP_LIB) $(OPENSSL_LIB) $(SECP256K1_LIB) $(NTL_LIB)
LIBS=-lzmq -lgmp -lm -lcrypto -lntl -lsecp256k1

all:
	cd Server; $(CC) $(CFLAGS) $(INCLUDE_PATH) *.cpp -o Server $(DEPS) $(LIBS)
	cd Client; $(CC) $(CFLAGS) $(INCLUDE_PATH) *.cpp -o Client $(DEPS) $(LIBS)

clean:
	cd Server; rm -f Server
	cd Client; rm -f Client

