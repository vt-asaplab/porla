/*
    @author:  Tung Le
    @email:   tungle@vt.edu
    @date:    June 15, 2022
    @warning: this is an academic proof-of-concept prototype and has not received careful code review. 
              this implementation is NOT ready for production use.
*/

#ifndef ___CONFIG_H_
#define ___CONFIG_H_

// Flag to store database
#define         TOP_CACHING_LEVEL           10

// #define         ENABLE_KZG                  1

const int       MAX_NUM_THREADS_SERVER      =  8;
const int       MAX_NUM_THREADS_CLIENT      =  8;
const int       SERVER_PORT                 =  8888;
const int       ID_SIZE                     =  sizeof(int);       
const int       BLOCK_SIZE                  =  (4092+ID_SIZE);                              
const int       NUM_CHUNKS                  =  (BLOCK_SIZE>>5);   
#ifndef ENABLE_KZG                            
const int       COMMITMENT_MAC_SIZE         =  sizeof(secp256k1_gej);   
#else 
const int       COMMITMENT_MAC_SIZE         =  64;
#endif
const int       NUM_GENERATORS              =  NUM_CHUNKS;
const int       MAX_BLOCKS_SENT             =  1024;

// The number of blocks in each level of H and C to perform audit
const int       NUM_CHECK_AUDIT             =  128;

// Secret key for PRF
const int       AES_DATA_SIZE               =  16;
const int       AES_KEY_SIZE                =  16;
const int       AES_IV_SIZE                 =  16;
const uint8_t   SECRET_KEY[16]              =  {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
const uint8_t   TAU_KEY[16]                 =  {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
const uint8_t   IV[16]                      =  {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

#endif
