#ifndef __UTILS_H_
#define __UTILS_H_

#include <NTL/vec_ZZ_p.h>
#include <NTL/vec_ZZ.h>
#include "libsecp256k1-config.h"
#include "secp256k1.c"
#include "secp256k1.h"
#include "secp256k1_preallocated.h"
#include "testrand_impl.h"
#include "Utils/ThreadPool.h"
#include "Utils/libmultiexp.h"
#include "Utils/prg.h"
#include <chrono>
#include <NTL/BasicThreadPool.h>
#include "config.hpp"
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fstream>

using namespace std;
using std::chrono::time_point;
using std::chrono::high_resolution_clock;

#ifndef ENABLE_KZG
std::string    GROUP_ORDER_STR("115792089237316195423570985008687907852837564279074904382605163141518161494337"); // Order of secp256k1
NTL::ZZ        GROUP_ORDER(NTL::INIT_VAL, GROUP_ORDER_STR.c_str());
std::string    GENERATOR_STR("37724658858582113439798596500054279666200959181261379108294206582568298678"); // A random value
NTL::ZZ        GENERATOR(NTL::INIT_VAL, GENERATOR_STR.c_str());
std::string    PRIME_MODULUS_STR("93628759656736142393278101159368737990730026663232799828780155818898507169793"); // 207 * 2^248 + 1
NTL::ZZ        PRIME_MODULUS(NTL::INIT_VAL, PRIME_MODULUS_STR.c_str());
std::string    LCM_STR("10841469693352021873483684275893008392101031472050201500515861578010683886271238884283113399568804205471204971859923723932950084770981108620251449466962241");
NTL::ZZ        LCM(NTL::INIT_VAL, LCM_STR.c_str());
#else 
std::string    GROUP_ORDER_STR("21888242871839275222246405745257275088548364400416034343698204186575808495617"); // Order of bn254
NTL::ZZ        GROUP_ORDER(NTL::INIT_VAL, GROUP_ORDER_STR.c_str());
std::string    GENERATOR_STR("37724658858582113439798596500054279666200959181261379108294206582568298678"); // A random value
NTL::ZZ        GENERATOR(NTL::INIT_VAL, GENERATOR_STR.c_str());
std::string    PRIME_MODULUS_STR("93628759656736142393278101159368737990730026663232799828780155818898507169793"); // 207 * 2^248 + 1
NTL::ZZ        PRIME_MODULUS(NTL::INIT_VAL, PRIME_MODULUS_STR.c_str());
std::string    LCM_STR("2049369031155707573937272810025244064710333118140408897690954651424664974620215782673575413484558574566298823256897068805013612518402283464943595715297281");
NTL::ZZ        LCM(NTL::INIT_VAL, LCM_STR.c_str());
#endif

// Definitions of data types
typedef   NTL::vec_ZZ   Data_Block;
typedef   NTL::vec_ZZ*  Data_Blocks;

struct Data_Layer 
{
    Data_Blocks X;
    Data_Blocks Y;
    bool empty;
};

struct Stored_Path 
{
    string      path;
    Data_Block  *data;
};

#ifdef ENABLE_KZG 
typedef   uint32_t        bn254_scalar[8];
typedef   uint64_t        MAC_Block[8];
typedef   MAC_Block*      MAC_Blocks;
#else 
typedef   secp256k1_gej   MAC_Block;
typedef   secp256k1_gej*  MAC_Blocks;
#endif 

struct MAC_Layer 
{
    MAC_Blocks X;
    MAC_Blocks Y;
    bool empty;
};

uint32_t temp[8];

long reverse_bits(long in, long n)
{
    long reverse = 0;
    for(int i = 0; i < n; ++i)
    {
        reverse <<= 1;
        reverse |= (in & 0x1);
        in      >>= 1;
    }
    return reverse;
}

#ifndef ENABLE_KZG
typedef struct {
    secp256k1_scalar *sc;
    secp256k1_ge *pt;
} ecmult_multi_data; 

typedef struct {
    secp256k1_scalar *sc;
    secp256k1_ge **pt;
} ecmult_multi_data_p; 

void random_field_element_test(secp256k1_fe *fe) {
    do {
        unsigned char b32[32];
        secp256k1_testrand256_test(b32);
        if (secp256k1_fe_set_b32(fe, b32)) {
            break;
        }
    } while(1);
}

void random_group_element_test(secp256k1_ge *ge) {
    secp256k1_fe fe;
    do {
        random_field_element_test(&fe);
        if (secp256k1_ge_set_xo_var(ge, &fe, secp256k1_testrand_bits(1))) {
            secp256k1_fe_normalize(&ge->y);
            break;
        }
    } while(1);
    ge->infinity = 0;
}

void random_scalar_order(secp256k1_scalar *num) {
    do {
        unsigned char b32[32];
        int overflow = 0;
        secp256k1_testrand256(b32);
        secp256k1_scalar_set_b32(num, b32, &overflow);
        if (overflow || secp256k1_scalar_is_zero(num)) {
            continue;
        }
        break;
    } while(1);
}

void ge_equals_ge(const secp256k1_ge *a, const secp256k1_ge *b) {
    CHECK(a->infinity == b->infinity);
    if (a->infinity) {
        return;
    }
    CHECK(secp256k1_fe_equal_var(&a->x, &b->x));
    CHECK(secp256k1_fe_equal_var(&a->y, &b->y));
    // printf("Result: %d, %d\n", secp256k1_fe_equal_var(&a->x, &b->x), secp256k1_fe_equal_var(&a->y, &b->y));
}

void ge_equals_gej(const secp256k1_ge *a, const secp256k1_gej *b) {
    secp256k1_fe z2s;
    secp256k1_fe u1, u2, s1, s2;
    CHECK(a->infinity == b->infinity);
    if (a->infinity) {
        return;
    }
    /* Check a.x * b.z^2 == b.x && a.y * b.z^3 == b.y, to avoid inverses. */
    secp256k1_fe_sqr(&z2s, &b->z);
    secp256k1_fe_mul(&u1, &a->x, &z2s);
    u2 = b->x; secp256k1_fe_normalize_weak(&u2);
    secp256k1_fe_mul(&s1, &a->y, &z2s); secp256k1_fe_mul(&s1, &s1, &b->z);
    s2 = b->y; secp256k1_fe_normalize_weak(&s2);
    CHECK(secp256k1_fe_equal_var(&u1, &u2));
    CHECK(secp256k1_fe_equal_var(&s1, &s2));
}

static int ecmult_multi_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *cbdata) {
    ecmult_multi_data *data = (ecmult_multi_data*) cbdata;
    *sc = data->sc[idx];
    *pt = data->pt[idx];
    return 1;
}

static int ecmult_multi_callback_p(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *cbdata) {
    ecmult_multi_data_p *data = (ecmult_multi_data_p*) cbdata;
    *sc = data->sc[idx];
    *pt = *(data->pt[idx]);
    return 1;
}

void convert_ZZ_to_scalar(secp256k1_scalar &scalar, NTL::ZZ &ZZ_value)
{
    NTL::ZZ  temp;
    conv(temp, ZZ_value);
    long val;
    uint32_t *d = (uint32_t*)scalar.d;
    for(int i = 0; i < 8; ++i)
    {
        conv(val, temp & 0xFFFFFFFF);
        d[i]   = val;
        temp >>= 32;
    }
}

void convert_scalar_to_ZZ(NTL::ZZ &ZZ_value, secp256k1_scalar &scalar)
{
    uint32_t *d = (uint32_t*)scalar.d;
    ZZ_value = 0;
    for(int i = 7; i >= 0; --i)
    {
        ZZ_value <<= 32;
        ZZ_value |= d[i];
    }
}

void convert_arr_to_scalar(secp256k1_scalar &scalar, uint32_t *value)
{
    uint32_t *d = (uint32_t*)scalar.d;
    for(int i = 0; i < 8; ++i)
        d[i] = value[i];
}

void write_MAC_to_file(std::string &file_path, MAC_Layer *data, int level)
{
    FILE *fo = fopen(file_path.c_str(), "wb");
    for(int i = 0; i < (1<<level); ++i)
    {
        fwrite(&data[level].X[i], sizeof(MAC_Block), 1, fo);
        fwrite(&data[level].Y[i], sizeof(MAC_Block), 1, fo);
    }
    fclose(fo);
}

void read_MAC_from_file(std::string &file_path, MAC_Layer *data, int level)
{
    FILE *fi = fopen(file_path.c_str(), "rb");
    for(int i = 0; i < (1<<level); ++i)
    {
        fread(&data[level].X[i], sizeof(MAC_Block), 1, fi);
        fread(&data[level].Y[i], sizeof(MAC_Block), 1, fi);
    }
    fclose(fi);
}

#else 
void bn254_add(MAC_Block a, MAC_Block b)
{
    GoSlice pa, pb;
    pa.len  = pa.cap = COMMITMENT_MAC_SIZE;
    pb.len  = pb.cap = COMMITMENT_MAC_SIZE;
    pa.data = a;
    pb.data = b;
    add_point(&pa, &pb);
}

void bn254_mult(MAC_Block a, bn254_scalar b)
{
    GoSlice pa, pb;
    pa.len  = pa.cap = COMMITMENT_MAC_SIZE;
    pb.len  = pb.cap = sizeof(bn254_scalar);
    pa.data = a;
    pb.data = b;
    mult_point(&pa, &pb);
}

void bn254_neg(MAC_Block b)
{
    GoSlice p;
    p.len  = p.cap = COMMITMENT_MAC_SIZE;
    p.data = b;
    neg_point(&p);
}

void bn254_set_infinity(MAC_Block b)
{
    GoSlice p;
    p.len  = p.cap = COMMITMENT_MAC_SIZE;
    p.data = b;
    set_inf_point(&p);
}

void bn254_scalar_set_int(bn254_scalar b, uint32_t value)
{
    b[0] = b[1] = b[2] = b[3] = b[4] = b[5] = b[6] = 0;
    b[7] = htonl(value);
}

void bn254_multi_exp(MAC_Block result, MAC_Block *points, bn254_scalar *scalars, int length)
{
    GoSlice gs_sc;
    gs_sc.data = (void*)scalars;
    gs_sc.len  = gs_sc.cap = (length<<5);

    GoSlice gs_pt;
    gs_pt.data = (void*)points;
    gs_pt.len  = gs_pt.cap = (length<<6);

    GoSlice gs_result;
    gs_result.data = (void*)result;
    gs_result.len  = gs_result.cap = 64;

    compute_multi_exp(&gs_sc, &gs_pt, length, &gs_result);
}

bool bn254_compare(MAC_Block a, MAC_Block b)
{
    GoSlice gs_a;
    gs_a.data = (void*)a;
    gs_a.len  = gs_a.cap = COMMITMENT_MAC_SIZE;

    GoSlice gs_b;
    gs_b.data = (void*)b;
    gs_b.len  = gs_b.cap = COMMITMENT_MAC_SIZE;

    return static_cast<bool>(compare_commitment(&gs_a, &gs_b));
}

void convert_ZZ_to_scalar(bn254_scalar scalar, const NTL::ZZ &ZZ_value)
{
    NTL::ZZ  temp;
    temp = ZZ_value;
    long val;
    for(int i = 7; i >= 0; --i)
    {
        conv(val, temp & 0xFFFFFFFF);
        scalar[i] = htonl(val);
        temp    >>= 32;
    }
}

void convert_scalar_to_ZZ(NTL::ZZ &ZZ_value, bn254_scalar scalar)
{
    ZZ_value = 0;
    for(int i = 7; i >= 0; --i)
    {
        ZZ_value <<= 32;
        ZZ_value |= scalar[i];
    }
}

void write_MAC_to_file(std::string &file_path, MAC_Layer *data, int level)
{
    FILE *fo = fopen(file_path.c_str(), "wb");
    for(int i = 0; i < (1<<level); ++i)
    {
        fwrite(data[level].X[i], sizeof(MAC_Block), 1, fo);
        fwrite(data[level].Y[i], sizeof(MAC_Block), 1, fo);
    }
    fclose(fo);
}

void read_MAC_from_file(std::string &file_path, MAC_Layer *data, int level)
{
    FILE *fi = fopen(file_path.c_str(), "rb");
    for(int i = 0; i < (1<<level); ++i)
    {
        fread(data[level].X[i], sizeof(MAC_Block), 1, fi);
        fread(data[level].Y[i], sizeof(MAC_Block), 1, fi);
    }
    fclose(fi);
}
#endif 

void convert_ZZ_to_arr(uint32_t *value, NTL::ZZ &ZZ_value)
{
    NTL::ZZ  temp;
    conv(temp, ZZ_value);
    long val;
    for(int i = 0; i < 8; ++i)
    {
        conv(val, temp & 0xFFFFFFFF);
        value[i] = val;
        temp   >>= 32;
    }
}

void convert_arr_to_ZZ(NTL::ZZ &ZZ_value, uint32_t *value)
{
    ZZ_value = 0;
    for(int i = 7; i >= 0; --i)
    {
        ZZ_value <<= 32;
        ZZ_value |= value[i];
    }
}

inline time_point<high_resolution_clock> clock_start() { 
	return high_resolution_clock::now();
}

inline double time_from(const time_point<high_resolution_clock>& s) {
	return std::chrono::duration_cast<std::chrono::microseconds>(high_resolution_clock::now() - s).count();
}

void convert_arr_to_ZZ_p(NTL::ZZ_p &ZZ_p_value, uint32_t* value)
{
    NTL::ZZ ZZ_value(0);
    for(int i = 7; i >= 0; --i) 
    {
        ZZ_value <<= 32;
        ZZ_value |=  value[i];
    }    
    conv(ZZ_p_value, ZZ_value);
}

int random_func(int j)
{
    return rand() % j;
}

void write_database_to_file(std::string &file_path, Data_Layer *data, int level)
{
    FILE *fo = fopen(file_path.c_str(), "wb");

    for(int i = 0; i < (1<<level); ++i)
    {
        for(int j = 0; j < NUM_CHUNKS; ++j)
        {
            convert_ZZ_to_arr(temp, data[level].X[i][j]);
            fwrite(temp, sizeof(temp), 1, fo);
        }
        for(int j = 0; j < NUM_CHUNKS; ++j)
        {
            convert_ZZ_to_arr(temp, data[level].Y[i][j]);
            fwrite(temp, sizeof(temp), 1, fo);
        }
    }
    fclose(fo);
}

void write_database_to_file(std::string &file_path, Data_Blocks data, int length)
{
    FILE *fo = fopen(file_path.c_str(), "wb");
    for(int i = 0; i < length; ++i)
    {
        for(int j = 0; j < NUM_CHUNKS; ++j)
        {
            convert_ZZ_to_arr(temp, data[i][j]);
            fwrite(temp, sizeof(temp), 1, fo);
        }
    }
    fclose(fo);
}

void read_database_from_file(std::string &file_path, Data_Layer *data, int level)
{
    FILE *fi = fopen(file_path.c_str(), "rb");

    for(int i = 0; i < (1<<level); ++i)
    {
        data[level].X[i].SetLength(NUM_CHUNKS);
        for(int j = 0; j < NUM_CHUNKS; ++j)
        {
            fread(temp, sizeof(temp), 1, fi);
            convert_arr_to_ZZ(data[level].X[i][j], temp);
            
        }
        data[level].Y[i].SetLength(NUM_CHUNKS);
        for(int j = 0; j < NUM_CHUNKS; ++j)
        {
            fread(temp, sizeof(temp), 1, fi);
            convert_arr_to_ZZ(data[level].Y[i][j], temp);
        }
    }
    fclose(fi);
}

void read_database_from_file(std::string &file_path, Data_Blocks data, int length)
{
    FILE *fi = fopen(file_path.c_str(), "rb");

    for(int i = 0; i < length; ++i)
    {
        data[i].SetLength(NUM_CHUNKS);
        for(int j = 0; j < NUM_CHUNKS; ++j)
        {
            fread(temp, sizeof(temp), 1, fi);
            convert_arr_to_ZZ(data[i][j], temp);
        }
    }
    fclose(fi);
}

inline void serialize_error_code_512b(uint32_t *value, NTL::ZZ &ZZ_value)
{
    NTL::ZZ temp;
    conv(temp, ZZ_value);
    long val;
    for(int i = 0; i < 16; ++i)
    {
        conv(val, temp & 0xFFFFFFFF);
        value[i] = val;
        temp   >>= 32;
    }
}

inline void deserialize_error_code_512b(NTL::ZZ &ZZ_value, uint32_t *value)
{
    ZZ_value = 0;
    for(int i = 15; i >= 0; --i)
    {
        ZZ_value <<= 32;
        ZZ_value |= value[i];
    }
}

inline void serialize_error_code_256b(uint32_t *value, NTL::ZZ &ZZ_value)
{
    NTL::ZZ temp;
    conv(temp, ZZ_value);
    long val;
    for(int i = 0; i < 8; ++i)
    {
        conv(val, temp & 0xFFFFFFFF);
        value[i] = val;
        temp   >>= 32;
    }
}

inline void deserialize_error_code_256b(NTL::ZZ &ZZ_value, uint32_t *value)
{
    ZZ_value = 0;
    for(int i = 7; i >= 0; --i)
    {
        ZZ_value <<= 32;
        ZZ_value |= value[i];
    }
}

inline void write_error_code_to_file_512b(string &prefix_path, Data_Block &data_block, int index)
{
    uint32_t value[16];
    string full_path = prefix_path + to_string(index);

    ofstream out_file(full_path, ios::binary);

    for(int i = 0; i < NUM_CHUNKS; ++i)
    {
        serialize_error_code_512b(value, data_block[i]);
        out_file.write((char*)value, sizeof(value));
    }

    out_file.close();
}

inline void read_error_code_from_file_512b(string &prefix_path, Data_Block &data_block, int index)
{
    uint32_t value[16];
    string full_path = prefix_path + to_string(index);
    data_block.SetLength(NUM_CHUNKS);

    ifstream in_file(full_path, ios::binary);

    for(int i = 0; i < NUM_CHUNKS; ++i)
    {
        in_file.read((char*)value, sizeof(value));
        deserialize_error_code_512b(data_block[i], value);
    }

    in_file.close();
}

inline void write_error_code_to_file_256b(string &prefix_path, Data_Block &data_block, int index)
{
    uint32_t value[8];
    string full_path = prefix_path + to_string(index);

    ofstream out_file(full_path, ios::binary);

    for(int i = 0; i < NUM_CHUNKS; ++i)
    {
        serialize_error_code_256b(value, data_block[i]);
        out_file.write((char*)value, sizeof(value));
    }

    out_file.close();
}

inline void read_error_code_from_file_256b(string &prefix_path, Data_Block &data_block, int index)
{
    uint32_t value[8];
    string full_path = prefix_path + to_string(index);
    data_block.SetLength(NUM_CHUNKS);

    ifstream in_file(full_path, ios::binary);

    for(int i = 0; i < NUM_CHUNKS; ++i)
    {
        in_file.read((char*)value, sizeof(value));
        deserialize_error_code_256b(data_block[i], value);
    }

    in_file.close();
}

inline void write_data_block_to_file(string &file_path, uint8_t *data_ptr)
{
    ofstream out_file(file_path, ios::binary);
    out_file.write((char*)data_ptr, BLOCK_SIZE);
    out_file.close();
}

inline void read_data_block_from_file(string &file_path, Data_Block &data_block)
{
    ifstream in_file(file_path, ios::binary);
    uint32_t value[8];
    data_block.SetLength(NUM_CHUNKS);
    for(int i = 0; i < NUM_CHUNKS; ++i)
    {
        in_file.read((char*)value, sizeof(value));
        data_block[i] = 0;
        for(int j = 7; j >= 0; --j)
        {
            data_block[i] <<= 32;
            data_block[i] |= value[j];
        }
    }
    in_file.close();
}

inline void read_error_code_from_file_256b(string &file_path, Data_Block &data_block)
{
    uint32_t value[8];
    ifstream in_file(file_path, ios::binary);
    data_block.SetLength(NUM_CHUNKS);

    for(int i = 0; i < NUM_CHUNKS; ++i)
    {
        in_file.read((char*)value, sizeof(value));
        deserialize_error_code_256b(data_block[i], value);
    }

    in_file.close();
}

inline void read_error_code_from_file_512b(string &file_path, Data_Block &data_block)
{
    uint32_t value[16];
    ifstream in_file(file_path, ios::binary);
    data_block.SetLength(NUM_CHUNKS);

    for(int i = 0; i < NUM_CHUNKS; ++i)
    {
        in_file.read((char*)value, sizeof(value));
        deserialize_error_code_512b(data_block[i], value);
    }
    
    in_file.close();
}

#endif
