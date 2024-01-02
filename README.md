# Efficient Dynamic Proof of Retrievability for Cold Storage
![x86](https://github.com/vt-asaplab/porla/blob/main/porla/Utils/workflows/x86/badge.svg)

This is our full implementation for our [Porla paper](https://dx.doi.org/10.14722/ndss.2023.23307). 

**WARNING**: This is an academic proof-of-concept prototype and has not received careful code review. This implementation is NOT ready for production use.

# Required Libraries

1. [NTL v11.5.1](http://www.shoup.net/ntl/download.html)

2. [ZeroMQ v4.8.1](https://github.com/zeromq/cppzmq/releases/tag/v4.8.1)

3. [Secp256k1](https://github.com/bitcoin-core/secp256k1/tree/423b6d19d373f1224fd671a982584d7e7900bc93) (**Note: checkout the correct branch as listed here**)

4. [Gnark-crypto v0.6.0](https://github.com/ConsenSys/gnark-crypto/releases/tag/v0.6.0)

You may need to modify paths of these libraries in the Makefile:

```
EDPOR/Makefile
```

# Build & Compile
[A Go compiler](https://go.dev/doc/install) is needed because we use [gnark-crypto](https://github.com/ConsenSys/gnark-crypto) library for our KZG-based scheme. Extract gnark-crypto ``v0.6.0.tar.gz`` and copy file **main.go** into the folder ``v0.6.0/gnark-crypto-0.6.0`` and compile it into a shared object dynamic library using the following command:  
```
go build -buildmode=c-shared -o libmultiexp.so main.go
```

Then copy file libmultiexp.so into the folder /usr/lib 

Go to the folder ``EDPOR`` and execute:
``` 
make
```
This is going to create executable files *Server* in **Server** folder and *Client* in **Client** folder.

## Testing

Before starting test, in folder ``Server``, we need to create 3 subfolders: **H_X**, **H_Y** and **U**. 

1. Launch server:
```
$ cd Server
$ ./Server
```
2. Launch client:
```
$ cd Client
$ ./Client [num_data_blocks]
```
You can start server/client applications in any order.

## Configuring IPA-based scheme and KZG-based scheme:
Comment/uncomment the line 7 ``#define         ENABLE_KZG                  1`` of file **config.hpp** and recompile.

## Configuring top-caching level:
Change the constant defined at the line 5 ``#define         TOP_CACHING_LEVEL           10`` of file **config.hpp** and recompile. 

## Error Correction Code (ICC)
Folder ``icc`` contains MATLAB code to examplify how to build Incrementally Constructible Code (ICC) implemented in Porla, as well as how to use ICC to recover data.

## Citing

If the code is found useful, we would be appreciated if our paper can be cited with the following bibtex format 

```
@inproceedings{le2022porla,
      author = {Tung Le and Pengzhi Huang and Attila A. Yavuz and Elaine Shi and Thang Hoang},
      title = {Efficient Dynamic Proof of Retrievability for Cold Storage},
      year = {2023},
      url = {https://eprint.iacr.org/2022/1417},
      doi = {10.14722/ndss.2023.23307},
      booktitle = {Network and Distributed Systems Security (NDSS) Symposium 2023},
}
```


# Further Information
For any inquiries, bugs, and assistance on building and running the code, please contact me at [tungle@vt.edu](mailto:tungle@vt.edu?Subject=[PORLA]%20Inquiry).

