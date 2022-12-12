/*
    @author:  Tung Le
    @email:   tungle@vt.edu
    @date:    June 15, 2022
    @warning: this is an academic proof-of-concept prototype and has not received careful code review. 
              this implementation is NOT ready for production use.
*/

#ifndef __SERVER_H_
#define __SERVER_H_

#include <cmath>
#include <random>
#include <zmq.hpp>
#include "Utils/utils.h"
#include "config.hpp"

using namespace      std;

int                  *audit_values;
PRG                  prg;
#ifndef ENABLE_KZG
MAC_Block            *commitment_parts;
secp256k1_context    *ctx;
secp256k1_ge         *pt;
secp256k1_ge         **ptp;
secp256k1_scalar     *sc;
secp256k1_scratch    **scratch;

secp256k1_scalar     **sc_array;
secp256k1_scratch    ***scratch_array;
MAC_Block            **commitment_array;

int                  bucket_window;
size_t               scratch_size;

// Constant 0
secp256k1_scalar     szero;
#else 
bn254_scalar         *sc;
bn254_scalar         **sc_array;
#endif 

class Server
{
public:
    // socket connection to client
    zmq::context_t      *context;
    zmq::socket_t       *socket;

    // total number of data blocks
    int                 num_blocks;
    // height of hierarchical log structure H
    int                 height;
#ifndef ENABLE_KZG
    // Generators g for computing commitments
    secp256k1_ge*       generators;        
    // Generator u for BulletProof 
    secp256k1_ge        u;         
#endif
    // Hierarchical log structure H of database      
    Data_Layer*         database_H; 
    // Hierarchical log structure H of MAC alignment
    MAC_Layer*          MAC_alignments_H;
    // MAC of Commitments
    MAC_Blocks          MAC_commitments_U;     
    // Log structure of H
    MAC_Layer*          MAC_commitments_H;     
    // the number of write operations so far
    long                write_step;

    // w is omega, the 2n-th primitive root of unity
    NTL::ZZ_p           w;
    
    Server();
    ~Server();

    void initialize();
#ifndef ENABLE_KZG
    void init_generators();
#endif 
    void update(uint8_t *update_info);
    void audit(uint8_t *audit_info);
#ifndef ENABLE_KZG
    void compute_commitment(Data_Block &data_block, MAC_Block &commitment);
    void inner_product_prove(NTL::vec_ZZ &a, NTL::vec_ZZ &b, uint8_t *proof);
#else 
    void create_kzg_proof(int random_point, Data_Block &data_block, uint8_t *kzg_proof);
#endif 
    void align_MAC(Data_Block &A, MAC_Block &B, int thread = 0);

    // Hierarchical log structure H - related functions of database H
    void HRebuildX(int level);
    void HRebuildY(int level);
    int  HAdd(Data_Block &data, MAC_Block &MAC);
    void mix(bool is_x, char *path, int level, bool is_last_step);
    void mix(bool is_x, int level);

    void clear_H_data(int until_level);
    void clear_H_MAC(int until_level);

    // CRebuild
    void CRebuild_Cached();
    void CRebuild_No_Cached();
    void CRebuild();

    // Functions for debugging
    void self_test();
};

Server::Server()
{
    context = new zmq::context_t(1);
    socket  = new zmq::socket_t(*context, ZMQ_REP);
    socket->bind("tcp://*:" + to_string(SERVER_PORT));
#ifndef ENABLE_KZG
    ctx     = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    pt      = (secp256k1_ge*)checked_malloc(&ctx->error_callback, sizeof(secp256k1_ge)*NUM_CHUNKS);
    ptp     = (secp256k1_ge**)checked_malloc(&ctx->error_callback, sizeof(secp256k1_ge*)*(NUM_CHUNKS>>1));

    bucket_window = secp256k1_pippenger_bucket_window(NUM_CHUNKS/MAX_NUM_THREADS_SERVER);
    scratch_size  = secp256k1_pippenger_scratch_size(NUM_CHUNKS/MAX_NUM_THREADS_SERVER, bucket_window);
    scratch_array = new secp256k1_scratch**[MAX_NUM_THREADS_SERVER];

    for(int i = 0; i < MAX_NUM_THREADS_SERVER; ++i)
    {
        scratch_array[i] = new secp256k1_scratch*[MAX_NUM_THREADS_SERVER];
        for(int j = 0; j < MAX_NUM_THREADS_SERVER; ++j)
            scratch_array[i][j] = secp256k1_scratch_create(&ctx->error_callback, scratch_size + PIPPENGER_SCRATCH_OBJECTS*ALIGNMENT);
    }
    
    sc_array = new secp256k1_scalar*[MAX_NUM_THREADS_SERVER];
    for(int i = 0; i < MAX_NUM_THREADS_SERVER; ++i)
        sc_array[i] = new secp256k1_scalar[NUM_CHUNKS];
    
    commitment_array = new MAC_Block*[MAX_NUM_THREADS_SERVER]; 
    for(int i = 0; i < MAX_NUM_THREADS_SERVER; ++i)
        commitment_array[i] = new MAC_Block[MAX_NUM_THREADS_SERVER];

    sc               = sc_array[0];
    scratch          = scratch_array[0];
    commitment_parts = commitment_array[0];

    secp256k1_scalar_set_int(&szero, 0);
#else 
    sc_array = new bn254_scalar*[MAX_NUM_THREADS_SERVER];
    for(int i = 0; i < MAX_NUM_THREADS_SERVER; ++i)
        sc_array[i] = new bn254_scalar[NUM_CHUNKS];
    sc = sc_array[0];
#endif
}

Server::~Server()
{

}

void Server::initialize()
{
    // Init NTL:ZZ_p
    NTL::ZZ_p::init(PRIME_MODULUS);
#ifndef ENABLE_KZG
    // Generators g for computing commitments
    init_generators();
    zmq::message_t generators_request;
    socket->recv(&generators_request);
    zmq::message_t reply_generators((NUM_GENERATORS+1)*sizeof(secp256k1_ge));

    uint8_t *data = (uint8_t*)reply_generators.data();
    for(int i = 0; i < NUM_GENERATORS; ++i)
    {
        memcpy((void*)data, &generators[i], sizeof(secp256k1_ge));
        data += sizeof(secp256k1_ge);
    }
    memcpy((void*)data, &u, sizeof(secp256k1_ge));
    // Send generators to client
    socket->send(reply_generators);
#else 
    zmq::message_t SRS_msg;
    socket->recv(&SRS_msg);
    cout << "SRS size: " << SRS_msg.size() << endl;

    GoInt   SRS_size;
    GoSlice SRS_data;
    SRS_data.data = (void*)SRS_msg.data();
    SRS_data.len = SRS_data.cap = NUM_CHUNKS*32+132;
    
    init_SRS_from_data(NUM_CHUNKS, &SRS_data);

    string reply_srs_msg = "RECEIVED SRS FROM CLIENT.";
    zmq::message_t reply_srs(reply_srs_msg.length());
    memcpy((void*)reply_srs.data(), reply_srs_msg.c_str(), reply_srs_msg.length());
    socket->send(reply_srs);
#endif 

    // Receive database from client
    cout << "Waiting for receiving database from client..." << endl;
    zmq::message_t database_request;
    socket->recv(&database_request);

    // Receive the number of data blocks
    num_blocks = *(int*)database_request.data();

    // Reply to server 
    string reply_message = "RECEIVED " + to_string(database_request.size()) + " BYTES FROM CLIENT.";
    zmq::message_t reply_msg(reply_message.length());
    memcpy((void*)reply_msg.data(), reply_message.c_str(), reply_message.length());
    socket->send(reply_msg);

    // Store database to memory
    MAC_commitments_U = new MAC_Block[num_blocks];

    // Initialize modular arithmetic parameters and FFT
    NTL::ZZ_p g = NTL::to_ZZ_p(GENERATOR);
    NTL::ZZ a   = (PRIME_MODULUS-1)/(2 * num_blocks);
    w           = NTL::power(g, a);

    write_step  = 0;
    height      = ceil(log2(num_blocks)) + 1;

    database_H         = new Data_Layer[height];
    MAC_alignments_H   = new MAC_Layer[height];
    MAC_commitments_H  = new MAC_Layer[height];

    int l = 2;
    for (int i = 0; i < height; i++) 
    {
        database_H[i].X            = new Data_Block[l];
        database_H[i].Y            = new Data_Block[l];
        database_H[i].empty        = true;
        
        MAC_alignments_H[i].X      = new MAC_Block[l];
        MAC_alignments_H[i].Y      = new MAC_Block[l];
        MAC_alignments_H[i].empty  = true;

        MAC_commitments_H[i].X     = new MAC_Block[l];
        MAC_commitments_H[i].Y     = new MAC_Block[l];
        MAC_commitments_H[i].empty = true;

        l                        <<= 1;
    }

    int remaining = num_blocks;
    int i = 0;
#ifndef ENABLE_KZG
    secp256k1_scalar data_chunk;
#else 
    bn254_scalar data_chunk;
#endif 
    while(remaining > 0)
    {
        // Wait for receiving data blocks
        socket->recv(&database_request);
        int num_blocks_received = database_request.size()/(BLOCK_SIZE + COMMITMENT_MAC_SIZE);
        uint8_t *data_ptr = (uint8_t*)database_request.data();
        int k = 0;
        while((k < num_blocks_received))
        {
            cout << "Block ID: " << *(int*)data_ptr << endl;
            string file_path = "U/" + to_string(i);
            write_data_block_to_file(file_path, data_ptr);
            data_ptr += BLOCK_SIZE;
            memcpy(&MAC_commitments_U[i], data_ptr, COMMITMENT_MAC_SIZE);
            data_ptr += COMMITMENT_MAC_SIZE;
            i++; k++;
        }

        // Reply successfully received
        reply_message = "RECEIVED " + to_string(database_request.size()) + " BYTES FROM CLIENT.";
        zmq::message_t reply_msg(reply_message.length());
        memcpy((void*)reply_msg.data(), reply_message.c_str(), reply_message.length());
        socket->send(reply_msg);
        
        remaining -= num_blocks_received;
    }
    
    // Wait for receiving updated MAC hiding parts
    socket->recv(&database_request);
    uint8_t *data_ptr = (uint8_t*)database_request.data();
    reply_message = "RECEIVED " + to_string(database_request.size()) + " BYTES FROM CLIENT.";
    zmq::message_t reply_msg_complements(reply_message.length());
    memcpy((void*)reply_msg_complements.data(), reply_message.c_str(), reply_message.length());
    socket->send(reply_msg_complements);

    // Build C 
    CRebuild();

    // Compute MACs of commitments
    MAC_Block MAC_complement;
    l = 1<<(height-1);
    for(int i = 0; i < (l<<1); ++i)
    {
#ifndef ENABLE_KZG
        memcpy(&MAC_complement, data_ptr, COMMITMENT_MAC_SIZE);
        if(i >= l)
            secp256k1_gej_add_var(&MAC_commitments_H[height-1].Y[i-l], &MAC_commitments_H[height-1].Y[i-l], &MAC_complement, NULL);
        else 
            secp256k1_gej_add_var(&MAC_commitments_H[height-1].X[i], &MAC_commitments_H[height-1].X[i], &MAC_complement, NULL);
#else 
        memcpy(MAC_complement, data_ptr, COMMITMENT_MAC_SIZE);
        if(i >= l)
            bn254_add(MAC_commitments_H[height-1].Y[i-l], MAC_complement);
        else
            bn254_add(MAC_commitments_H[height-1].X[i], MAC_complement);
#endif
        data_ptr += COMMITMENT_MAC_SIZE;
    }
    
    // Allocate a buffer for audit operation
    audit_values = new int[(NUM_CHECK_AUDIT<<1)*height];
}

#ifndef ENABLE_KZG
void Server::init_generators()
{
    // Initialize generator g for computing commitments
    generators = new secp256k1_ge[NUM_GENERATORS]; 

    secp256k1_scalar PRIME_SCALAR;
    convert_ZZ_to_scalar(PRIME_SCALAR, PRIME_MODULUS);
    
    secp256k1_gej temp;
    for(int i = 0; i < NUM_GENERATORS; ++i)
        random_group_element_test(&generators[i]);
    
    random_group_element_test(&u);
}

void Server::compute_commitment(Data_Block &data_block, MAC_Block &commitment)
{
    vector<future<void>> res;
    ThreadPool pool(MAX_NUM_THREADS_SERVER);

    int start_chunk = 0;
    int end_chunk   = NUM_CHUNKS/MAX_NUM_THREADS_SERVER;
    
    for(int t = 0; t < MAX_NUM_THREADS_SERVER; ++t)
    {
        res.push_back(pool.enqueue([this, t, start_chunk, end_chunk, &data_block]() 
        {
            int n_points = NUM_CHUNKS/MAX_NUM_THREADS_SERVER;
            ecmult_multi_data data; 
            for(int i = start_chunk; i < end_chunk; ++i)
                convert_ZZ_to_scalar(sc[i], data_block[i]);

            data.sc = &sc[start_chunk];
            data.pt = &generators[start_chunk];

            secp256k1_ecmult_multi_var(&ctx->error_callback, scratch[t], &commitment_parts[t], &szero, ecmult_multi_callback, &data, n_points);
        }));
        start_chunk = end_chunk;
        end_chunk  += NUM_CHUNKS/MAX_NUM_THREADS_SERVER;
    }

    for(auto &v: res) v.get();
	res.clear();

    secp256k1_gej_set_infinity(&commitment);
    for(int t = 0; t < MAX_NUM_THREADS_SERVER; ++t)
        secp256k1_gej_add_var(&commitment, &commitment, &commitment_parts[t], NULL);
}
#else 
void Server::create_kzg_proof(int random_point, Data_Block &data_block, uint8_t *kzg_proof)
{
    MAC_Block commitment;
    GoSlice gs_commitment;
    gs_commitment.data = (void*)commitment;
    gs_commitment.len  = gs_commitment.cap = 64;

    MAC_Block proof_H;
    GoSlice gs_proof_H;
    gs_proof_H.data = (void*)proof_H;
    gs_proof_H.len  = gs_proof_H.cap = 64;

    GoSlice gs_proof_point; 
    bn254_scalar proof_point;
    gs_proof_point.data = (void*)proof_point;
    gs_proof_point.len  = gs_proof_point.cap = 32;

    GoSlice gs_proof_claim;
    bn254_scalar proof_claim;
    gs_proof_claim.data = (void*)proof_claim;
    gs_proof_claim.len  = gs_proof_claim.cap = 32;

    GoSlice gs_data_in;
    gs_data_in.data = (void*)sc;
    gs_data_in.len  = gs_data_in.cap = BLOCK_SIZE;
    
    for(int i = 0; i < NUM_CHUNKS; ++i) 
        convert_ZZ_to_scalar(sc[i], data_block[i]);

    create_proof(random_point, &gs_data_in, &gs_commitment, &gs_proof_H, &gs_proof_point, &gs_proof_claim);
    
    memcpy(kzg_proof,     commitment,  64);
    memcpy(kzg_proof+64,  proof_H,     64);
    memcpy(kzg_proof+128, proof_point, 32);
    memcpy(kzg_proof+160, proof_claim, 32);
}
#endif 

void Server::update(uint8_t *update_info)
{
    // Copy received data to stored database U
    uint8_t *data_ptr = update_info;
#ifndef ENABLE_KZG
    secp256k1_scalar data_chunk;
    int index = *(uint64_t*)update_info;
#else 
    bn254_scalar data_chunk;
    int index = *(uint64_t*)update_info;
#endif 
    
    string file_path = "U/" + to_string(index-1);
    write_data_block_to_file(file_path, data_ptr);

    Data_Block data_block;
    data_block.SetLength(NUM_CHUNKS);
    
    for(int i = 0; i < NUM_CHUNKS; ++i)
    {
        convert_arr_to_ZZ(data_block[i], (uint32_t*)data_ptr);
        data_ptr += 32;
    }

    // Update MAC of commitment
    uint8_t *data_complements = data_ptr;
    memcpy(&MAC_commitments_U[index-1], data_complements, COMMITMENT_MAC_SIZE);
    data_complements += COMMITMENT_MAC_SIZE;
    
    // Update write time
    write_step++;

    int updated_level = height-1;
    if(write_step % num_blocks == 0)
    {
        // Rebuild C
        cout << "WRITE STEP #" << write_step << " - C IS REBUILT" << endl;
        CRebuild();
    }
    else 
    {
        // Update H
        cout << "WRITE STEP #" << write_step << " - H IS UPDATED" << endl;
        // Add to hierarchical log structure H
        updated_level = HAdd(data_block, MAC_commitments_U[index-1]);
        // print_H();
    }

    // Update MAC hiding parts
    int l = (1<<updated_level);
    MAC_Block MAC_complement;
    
    for(int i = 0; i < (l<<1); ++i)
    {
        memcpy(&MAC_complement, data_complements, COMMITMENT_MAC_SIZE);
        if(i >= l)
#ifndef ENABLE_KZG
            secp256k1_gej_add_var(&MAC_commitments_H[updated_level].Y[i-l], &MAC_commitments_H[updated_level].Y[i-l], &MAC_complement, NULL);
#else 
            bn254_add(MAC_commitments_H[updated_level].Y[i-l], MAC_complement);
#endif 
        else 
#ifndef ENABLE_KZG
            secp256k1_gej_add_var(&MAC_commitments_H[updated_level].X[i], &MAC_commitments_H[updated_level].X[i], &MAC_complement, NULL);
#else 
            bn254_add(MAC_commitments_H[updated_level].X[i], MAC_complement);
#endif 
        data_complements += COMMITMENT_MAC_SIZE; 
    } 
    
    // Reply    
    string response = "BLOCK " + to_string(index) + " IS UPDATED.";
    zmq::message_t reply(response.length());
    memcpy((void*)reply.data(), response.c_str(), response.length());
    socket->send(reply);
}

void Server::align_MAC(Data_Block &A, MAC_Block &B, int thread)
{
#ifndef ENABLE_KZG
    secp256k1_scratch **scratch = scratch_array[thread];
    MAC_Block *commitments      = commitment_array[thread];
    secp256k1_scalar *sc        = sc_array[thread];

    vector<future<void>> res;
    ThreadPool pool(MAX_NUM_THREADS_SERVER);

    int start_chunk = 0;
    int end_chunk   = NUM_CHUNKS/MAX_NUM_THREADS_SERVER;
    
    for(int t = 0; t < MAX_NUM_THREADS_SERVER; ++t)
    {
        res.push_back(pool.enqueue([this, t, start_chunk, end_chunk, &A, sc, commitments, scratch]() 
        {
            NTL::ZZ mod, c;

            for(int i = start_chunk; i < end_chunk; ++i)
            {
                mod  = A[i] % PRIME_MODULUS;
                c    = mod - A[i];  
                A[i] = mod;
                c   %= GROUP_ORDER;
                convert_ZZ_to_scalar(sc[i], c);
            }
            ecmult_multi_data data; 
            data.sc = &sc[start_chunk];
            data.pt = &generators[start_chunk];

            secp256k1_ecmult_multi_var(&ctx->error_callback, scratch[t], &commitments[t], &szero, ecmult_multi_callback, &data, NUM_CHUNKS/MAX_NUM_THREADS_SERVER);
        }));
        start_chunk = end_chunk;
        end_chunk  += NUM_CHUNKS/MAX_NUM_THREADS_SERVER;
    }
    for(auto &v: res) v.get();
	res.clear();

    for(int j = 0; j < MAX_NUM_THREADS_SERVER; ++j)
        secp256k1_gej_add_var(&B, &B, &commitments[j], NULL);
#else 
    vector<future<void>> res;
    ThreadPool pool(MAX_NUM_THREADS_SERVER);
    bn254_scalar *sc = sc_array[thread];

    int start_chunk = 0;
    int end_chunk   = NUM_CHUNKS/MAX_NUM_THREADS_SERVER;
    
    for(int t = 0; t < MAX_NUM_THREADS_SERVER; ++t)
    {
        res.push_back(pool.enqueue([this, t, start_chunk, end_chunk, &A, sc]() 
        {
            NTL::ZZ mod, c;

            for(int i = start_chunk; i < end_chunk; ++i)
            {
                mod  = A[i] % PRIME_MODULUS;
                c    = mod - A[i];  
                A[i] = mod;
                c   %= GROUP_ORDER;
                convert_ZZ_to_scalar(sc[i], c);
            }
        }));
        start_chunk = end_chunk;
        end_chunk  += NUM_CHUNKS/MAX_NUM_THREADS_SERVER;
    }
    for(auto &v: res) v.get();
	res.clear();

    MAC_Block align_value;

    GoSlice gs_data_in;
    gs_data_in.data = (void*)sc;
    gs_data_in.len  = gs_data_in.cap = BLOCK_SIZE;
    
    GoSlice gs_commitment;
    gs_commitment.data = (void*)align_value;
    gs_commitment.len  = gs_commitment.cap = 64;
    
    compute_digest_from_srs(&gs_data_in, &gs_commitment);

    bn254_add(B, align_value);
#endif 
}

void Server::audit(uint8_t *audit_info)
{
    NTL::vec_ZZ B;
    B.SetLength(NUM_CHUNKS);
    B *= 0;

    int index;
    int coeff;
    int l = 1;
    int n_points = 0;
#ifndef ENABLE_KZG
    secp256k1_gej     combined_MAC;
    secp256k1_gej     combined_align;
    secp256k1_ge      temp;

    secp256k1_scalar  *sc  = new secp256k1_scalar[NUM_CHECK_AUDIT*height];
    secp256k1_ge      *ptc = new secp256k1_ge[NUM_CHECK_AUDIT*height];
    secp256k1_ge      *pta = new secp256k1_ge[NUM_CHECK_AUDIT*height];
#else 
    MAC_Block        combined_MAC;
    MAC_Block        combined_align;
    bn254_scalar     *sc   = new bn254_scalar[NUM_CHECK_AUDIT*height];
    MAC_Block        *ptc  = new MAC_Block[NUM_CHECK_AUDIT*height];
    MAC_Block        *pta  = new MAC_Block[NUM_CHECK_AUDIT*height];
#endif 
    Stored_Path  *stored_paths  = new Stored_Path[NUM_CHECK_AUDIT*height];
    int          *stored_coefs  = new int[NUM_CHECK_AUDIT*height];
    NTL::vec_ZZ  **stored_vects = new NTL::vec_ZZ*[NUM_CHECK_AUDIT*height];

    auto start = clock_start();
    
    block seed;
    memcpy(&seed, audit_info, sizeof(block));
    prg.reseed(&seed, 0);
    prg.random_data((void*)audit_values, sizeof(int)*(NUM_CHECK_AUDIT<<1)*height);

    int *audit_values_ptr = audit_values;
    
    int count = 0;

    for(int i = 0; i < height; ++i)
    {
        if(((write_step % num_blocks)>>i) & 0x1 || (i == height-1))
        {
            if((l<<1) > NUM_CHECK_AUDIT)
            {
                int *indices      = audit_values_ptr;
                int *coeffs       = audit_values_ptr + NUM_CHECK_AUDIT;
                audit_values_ptr += (NUM_CHECK_AUDIT<<1);

                for(int j = 0; j < NUM_CHECK_AUDIT; ++j)
                {
                    int index = abs(indices[j]) % (l<<1);
                    int coeff = abs(coeffs[j]);
#ifndef ENABLE_KZG
                    secp256k1_scalar_set_int(&sc[n_points], coeff);
#else 
                    bn254_scalar_set_int(sc[n_points], coeff);
#endif
                    if(index >= l) 
                    {
                        stored_coefs[n_points] = coeff;
                        if(i > TOP_CACHING_LEVEL)
                        {
                            stored_paths[count].path = "H_Y/" + to_string(i) + "_" + to_string(index-l);
                            stored_vects[n_points]   = new NTL::vec_ZZ;
                            stored_paths[count].data = stored_vects[n_points];
                            count++;
                        }
                        else 
                        {
                            stored_vects[n_points] = &database_H[i].Y[index-l];
                        }
#ifndef ENABLE_KZG  
                        secp256k1_ge_set_gej(&ptc[n_points], &MAC_commitments_H[i].Y[index-l]);
                        secp256k1_ge_set_gej(&pta[n_points], &MAC_alignments_H[i].Y[index-l]);
#else 
                        memcpy(ptc[n_points], MAC_commitments_H[i].Y[index-l], COMMITMENT_MAC_SIZE);
                        memcpy(pta[n_points], MAC_alignments_H[i].Y[index-l], COMMITMENT_MAC_SIZE);
#endif
                    }
                    else
                    {
                        stored_coefs[n_points] = coeff;
                        if(i > TOP_CACHING_LEVEL)
                        {
                            stored_paths[count].path = "H_X/" + to_string(i) + "_" + to_string(index);
                            stored_vects[n_points]   = new NTL::vec_ZZ;
                            stored_paths[count].data = stored_vects[n_points];
                            count++;
                        }
                        else 
                        {
                            stored_vects[n_points] = &database_H[i].X[index];
                        }
#ifndef ENABLE_KZG
                        secp256k1_ge_set_gej(&ptc[n_points], &MAC_commitments_H[i].X[index]);
                        secp256k1_ge_set_gej(&pta[n_points], &MAC_alignments_H[i].X[index]);
#else 
                        memcpy(ptc[n_points], MAC_commitments_H[i].X[index], COMMITMENT_MAC_SIZE);
                        memcpy(pta[n_points], MAC_alignments_H[i].X[index], COMMITMENT_MAC_SIZE);
#endif
                    } 
                    n_points++;
                }
            }
            else 
            {
                int *coeffs       = audit_values_ptr;
                audit_values_ptr += (l<<1);

                for(int j = 0; j < (l<<1); ++j)
                {
                    int coeff = abs(coeffs[j]);
#ifndef ENABLE_KZG
                    secp256k1_scalar_set_int(&sc[n_points], coeff);
#else 
                    bn254_scalar_set_int(sc[n_points], coeff);
#endif
                    if(j >= l)
                    {
                        stored_coefs[n_points] = coeff;
                        if(i > TOP_CACHING_LEVEL)
                        {
                            stored_paths[count].path = "H_Y/" + to_string(i) + "_" + to_string(j-l);
                            stored_vects[n_points]   = new NTL::vec_ZZ;
                            stored_paths[count].data = stored_vects[n_points];
                            count++;
                        }
                        else 
                        {
                            stored_vects[n_points] = &database_H[i].Y[j-l];
                        }
#ifndef ENABLE_KZG
                        secp256k1_ge_set_gej(&ptc[n_points], &MAC_commitments_H[i].Y[j-l]);
                        secp256k1_ge_set_gej(&pta[n_points], &MAC_alignments_H[i].Y[j-l]);
#else 
                        memcpy(ptc[n_points], MAC_commitments_H[i].Y[j-l], COMMITMENT_MAC_SIZE);
                        memcpy(pta[n_points], MAC_alignments_H[i].Y[j-l], COMMITMENT_MAC_SIZE);
#endif
                    }
                    else
                    {
                        stored_coefs[n_points] = coeff;
                        if(i > TOP_CACHING_LEVEL)
                        {
                            stored_paths[count].path = "H_X/" + to_string(i) + "_" + to_string(j);
                            stored_vects[n_points]   = new NTL::vec_ZZ;
                            stored_paths[count].data = stored_vects[n_points];
                            count++;
                        }
                        else 
                        {
                            stored_vects[n_points] = &database_H[i].X[j];
                        }
#ifndef ENABLE_KZG
                        secp256k1_ge_set_gej(&ptc[n_points], &MAC_commitments_H[i].X[j]);    
                        secp256k1_ge_set_gej(&pta[n_points], &MAC_alignments_H[i].X[j]);  
#else 
                        memcpy(ptc[n_points], MAC_commitments_H[i].X[j], COMMITMENT_MAC_SIZE);
                        memcpy(pta[n_points], MAC_alignments_H[i].X[j], COMMITMENT_MAC_SIZE);
#endif
                    } 
                    n_points++;
                }
            }
        }
        l <<= 1;
    }   

    vector<future<void>> res;
    ThreadPool pool(MAX_NUM_THREADS_SERVER);
    cout << "Count: " << count << endl;
    int n_elems_per_thread = round((double)count/MAX_NUM_THREADS_SERVER);

    int start_pos = 0;
    int end_pos   = n_elems_per_thread;

    vector<int> shuffled_indices(count);
    iota(shuffled_indices.begin(), shuffled_indices.end(), 0);
    random_shuffle(shuffled_indices.begin(), shuffled_indices.end(), random_func);

    auto start_reading = clock_start();

    for(int t = 0; t < MAX_NUM_THREADS_SERVER-1; ++t)
    {
        res.push_back(pool.enqueue([this, t, start_pos, end_pos, stored_paths, shuffled_indices]() 
        {
            auto start = clock_start();
            for(int i = start_pos; i < end_pos; ++i)
                read_error_code_from_file_256b(stored_paths[shuffled_indices[i]].path, *(stored_paths[shuffled_indices[i]].data));
            
            cout << "Read " << (end_pos - start_pos) << " items - Time thread #" << t << ": " << time_from(start) << endl;
	    }));
        start_pos = end_pos;
        end_pos  += n_elems_per_thread;
    }
    
    end_pos -= n_elems_per_thread;
    
    res.push_back(pool.enqueue([this, end_pos, count, stored_paths, shuffled_indices]() 
    {
        auto start = clock_start();
        for(int i = end_pos; i < count; ++i)
            read_error_code_from_file_256b(stored_paths[shuffled_indices[i]].path, *(stored_paths[shuffled_indices[i]].data));
        
    	cout << "Read " << (count - end_pos) << " items - Time thread #" << (MAX_NUM_THREADS_SERVER-1) << ": " << time_from(start) << endl;
    }));
    
    for(auto &v: res) v.get();
	res.clear();

    cout << "Reading time: " << time_from(start_reading) << endl;

    vector<int> ivec(n_points);
    iota(ivec.begin(), ivec.end(), 0);
    random_shuffle(ivec.begin(), ivec.end(), random_func);

    n_elems_per_thread   = round((double)n_points/MAX_NUM_THREADS_SERVER);
    NTL::vec_ZZ *B_parts = new NTL::vec_ZZ[MAX_NUM_THREADS_SERVER];

    start_pos = 0;
    end_pos   = n_elems_per_thread;
    
    auto start_computing = clock_start();

    for(int t = 0; t < MAX_NUM_THREADS_SERVER-1; ++t)
    {
        res.push_back(pool.enqueue([this, t, start_pos, end_pos, B_parts, stored_coefs, stored_vects, &ivec]() 
        {
            auto start = clock_start();
            B_parts[t].SetLength(NUM_CHUNKS);
            for(int i = start_pos; i < end_pos; ++i)
            {
                int real_index = ivec[i];
		        for(int j = 0; j < NUM_CHUNKS; ++j)
                    B_parts[t][j] += stored_coefs[real_index] * (*stored_vects[real_index])[j];
	        }
            cout << "Time thread #" << t << ": " << time_from(start) << endl;
	    }));
        start_pos = end_pos;
        end_pos  += n_elems_per_thread;
    }
    
    end_pos -= n_elems_per_thread;
    
    res.push_back(pool.enqueue([this, end_pos, n_points, B_parts, stored_coefs, stored_vects, &ivec]() 
    {
        auto start = clock_start();
        B_parts[MAX_NUM_THREADS_SERVER-1].SetLength(NUM_CHUNKS);
        for(int i = end_pos; i < n_points; ++i)
        {
            int real_index = ivec[i];
            for(int j = 0; j < NUM_CHUNKS; ++j)
                B_parts[MAX_NUM_THREADS_SERVER-1][j] += stored_coefs[real_index] * (*stored_vects[real_index])[j];
        }
    	cout << "Time thread #" << (MAX_NUM_THREADS_SERVER-1) << ": " << time_from(start) << endl;
    }));
    
    for(auto &v: res) v.get();
	res.clear();
    
    cout << "Computing time: " << time_from(start_computing) << endl;
    for(int i = 0; i < MAX_NUM_THREADS_SERVER; ++i)
        B += B_parts[i];

    cout << "Preparation time: " << time_from(start) << endl;
#ifndef ENABLE_KZG
    auto start_prove = clock_start();
    
    ecmult_multi_data data; 
    data.sc = sc;
    data.pt = ptc;

    int    bucket_window = secp256k1_pippenger_bucket_window(n_points);
    size_t scratch_size  = secp256k1_pippenger_scratch_size(n_points, bucket_window);
    secp256k1_scratch *scratch = secp256k1_scratch_create(&ctx->error_callback, scratch_size + PIPPENGER_SCRATCH_OBJECTS*ALIGNMENT);
    /* Note for future optimization: ecmult_multi_var can be accomplished in parallel */
    secp256k1_ecmult_multi_var(&ctx->error_callback, scratch, &combined_MAC, &szero, ecmult_multi_callback, &data, n_points);

    data.sc = sc;
    data.pt = pta;
    secp256k1_gej_set_infinity(&combined_align);
    /* Note for future optimization: ecmult_multi_var can be accomplished in parallel */
    secp256k1_ecmult_multi_var(&ctx->error_callback, scratch, &combined_align, &szero, ecmult_multi_callback, &data, n_points);

    align_MAC(B, combined_align);
    
    MAC_Block commitment;
    compute_commitment(B, commitment);
    
    // Create BulletProof
    int proof_len  = 32 + ((int)log2(NUM_CHUNKS)-1)*66 + 128;
    uint8_t *proof = new uint8_t[proof_len];

    NTL::vec_ZZ A;
    NTL::ZZ     A_value;
    conv(A_value, audit_values[n_points]);
    A.SetLength(NUM_CHUNKS);
    for(int i = 0; i < NUM_CHUNKS; ++i)
    {
        A[i] = A_value;
        A_value = (A_value * A_value) % GROUP_ORDER;
    }

    res.push_back(pool.enqueue([this, &B, &A, proof]() 
    {
        NTL::ZZ_p::init(GROUP_ORDER);
        inner_product_prove(B, A, proof);
    }));
    for(auto &v: res) v.get();
	res.clear();
    
    cout << "Proving time: " << time_from(start_prove) << endl;

    // Send all information to client
    zmq::message_t reply(33*3 + proof_len);
    size_t size;
    
    secp256k1_ge_set_gej(&temp, &commitment);
    secp256k1_eckey_pubkey_serialize(&temp, (uint8_t*)reply.data(), &size, 1);

    secp256k1_ge_set_gej(&temp, &combined_MAC);
    secp256k1_eckey_pubkey_serialize(&temp, (uint8_t*)reply.data()+33, &size, 1);

    secp256k1_ge_set_gej(&temp, &combined_align);
    secp256k1_eckey_pubkey_serialize(&temp, (uint8_t*)reply.data()+66, &size, 1);

    memcpy((uint8_t*)reply.data()+99, proof, proof_len);

    socket->send(reply);  

    delete [] proof;
#else 
    start = clock_start();

    bn254_multi_exp(combined_MAC, ptc, sc, n_points);
    bn254_multi_exp(combined_align, pta, sc, n_points);

    align_MAC(B, combined_align);

    uint8_t *kzg_proof = new uint8_t[192];

    create_kzg_proof(*audit_values_ptr, B, kzg_proof);
    cout << "Time to create proof: " << time_from(start) << endl;
    
    // Send all information to client
    zmq::message_t reply(192 + COMMITMENT_MAC_SIZE*2);
    memcpy((void*)reply.data(), kzg_proof, 192);
    memcpy((void*)(reply.data()+192), combined_MAC, COMMITMENT_MAC_SIZE);
    memcpy((void*)(reply.data()+192+COMMITMENT_MAC_SIZE), combined_align, COMMITMENT_MAC_SIZE);

    socket->send(reply);

    delete [] kzg_proof;
#endif

    delete [] sc;
    delete [] ptc;
    delete [] pta;
    delete [] stored_paths;
    delete [] stored_coefs;
    for(int i = 0; i < n_points; ++i)
        if(stored_paths[i].path.length() > 0)
            delete stored_paths[i].data;
    delete [] stored_vects;
    delete [] B_parts;
}

void Server::self_test()
{
    while(1)
    {
        zmq::message_t request;
        socket->recv(&request);

        char op = *(char*)request.data();
        switch(op)
        {
            case 'A':
                audit((uint8_t*)request.data() + 1);
                break;
            case 'U':
                // Update
                update((uint8_t*)request.data() + 1);
                break;
        }
    }
}

void Server::mix(bool is_x, char *path, int level, bool is_last_step)
{
    cout << "Mix is called at level: " << level << endl;
    int length    = 1 << level;
    int n_threads = (length >= MAX_NUM_THREADS_SERVER) ? MAX_NUM_THREADS_SERVER : length;
    
    vector<future<void>> res;
    ThreadPool pool(MAX_NUM_THREADS_SERVER);

    int start_pos = 0;
    int end_pos   = length/n_threads;
    
    MAC_Blocks MAC_A0, MAC_A1, MAC_A;
    MAC_Blocks MAC_align_A0, MAC_align_A1, MAC_align_A;
    
    if(is_x)
    {
        MAC_A0       = MAC_commitments_H[level].X;
        MAC_A1       = &MAC_commitments_H[level].X[length];
        MAC_A        = &MAC_commitments_H[level+1].X[length<<1];
        MAC_align_A0 = MAC_alignments_H[level].X;
        MAC_align_A1 = &MAC_alignments_H[level].X[length];
        MAC_align_A  = &MAC_alignments_H[level+1].X[length<<1];
    }
    else 
    {
        MAC_A0       = MAC_commitments_H[level].Y;
        MAC_A1       = &MAC_commitments_H[level].Y[length];
        MAC_A        = &MAC_commitments_H[level+1].Y[length<<1];
        MAC_align_A0 = MAC_alignments_H[level].Y;
        MAC_align_A1 = &MAC_alignments_H[level].Y[length];
        MAC_align_A  = &MAC_alignments_H[level+1].Y[length<<1];
    }
    
    if(level <= TOP_CACHING_LEVEL)
    {
        Data_Blocks data_A0, data_A1;
        if(is_x)
        {
            data_A0      = database_H[level].X;
            data_A1      = &database_H[level].X[length];
        }
        else 
        {
            data_A0      = database_H[level].Y;
            data_A1      = &database_H[level].Y[length];
        }

        for(int t = 0; t < n_threads; ++t)
        {
            res.push_back(pool.enqueue([this, t, data_A0, data_A1, MAC_A0, MAC_A1, MAC_A,
                                        MAC_align_A0, MAC_align_A1, MAC_align_A, start_pos, 
                                        end_pos, is_x, path, level, length, is_last_step]() 
            {            
                NTL::ZZ_p::init(PRIME_MODULUS);
                NTL::ZZ_p v  = NTL::power(w, num_blocks/length);
                NTL::ZZ_p vi = power(v, start_pos);
                NTL::ZZ   vi_ZZ;
                conv(vi_ZZ, vi);
    #ifndef ENABLE_KZG
                secp256k1_scalar vi_MAC;
                secp256k1_gej    value_MAC;
    #else 
                bn254_scalar     vi_MAC;
                MAC_Block        value_MAC;
    #endif 
                NTL::ZZ value;
                Data_Block A, AL;
                A.SetLength(NUM_CHUNKS);
                AL.SetLength(NUM_CHUNKS);

                string prefix_path_out = path + to_string(level+1) + "_";

                for (int i = start_pos; i < end_pos; ++i)
                {
                    for(int j = 0; j < NUM_CHUNKS; ++j)
                    {
                        value = vi_ZZ * data_A1[i][j];
                        A[j]  = (data_A0[i][j] + value) % LCM;
                        AL[j] = (data_A0[i][j] - value) % LCM;
                    }
                    
                    convert_ZZ_to_scalar(vi_MAC, vi_ZZ);
    #ifndef ENABLE_KZG
                    // Process MAC parts
                    secp256k1_ecmult(&value_MAC, &MAC_A1[i], &vi_MAC, NULL);
                    secp256k1_gej_add_var(&MAC_A[i], &MAC_A0[i], &value_MAC, NULL); 

                    secp256k1_gej_neg(&value_MAC, &value_MAC);
                    secp256k1_gej_add_var(&MAC_A[i+length], &MAC_A0[i], &value_MAC, NULL);

                    // Process alignment parts
                    secp256k1_ecmult(&value_MAC, &MAC_align_A1[i], &vi_MAC, NULL);
                    secp256k1_gej_add_var(&MAC_align_A[i], &MAC_align_A0[i], &value_MAC, NULL); 

                    secp256k1_gej_neg(&value_MAC, &value_MAC);
                    secp256k1_gej_add_var(&MAC_align_A[i+length], &MAC_align_A0[i], &value_MAC, NULL);
    #else 
                    // Process MAC parts
                    memcpy(value_MAC, MAC_A1[i], COMMITMENT_MAC_SIZE);
                    bn254_mult(value_MAC, vi_MAC);

                    memcpy(MAC_A[i], MAC_A0[i], COMMITMENT_MAC_SIZE);
                    bn254_add(MAC_A[i], value_MAC); 

                    bn254_neg(value_MAC);
                    memcpy(MAC_A[i+length], MAC_A0[i], COMMITMENT_MAC_SIZE);
                    bn254_add(MAC_A[i+length], value_MAC);

                    // Process alignment parts
                    memcpy(value_MAC, MAC_align_A1[i], COMMITMENT_MAC_SIZE);
                    bn254_mult(value_MAC, vi_MAC);

                    memcpy(MAC_align_A[i], MAC_align_A0[i], COMMITMENT_MAC_SIZE);
                    bn254_add(MAC_align_A[i], value_MAC); 

                    bn254_neg(value_MAC);
                    memcpy(MAC_align_A[i+length], MAC_align_A0[i], COMMITMENT_MAC_SIZE);
                    bn254_add(MAC_align_A[i+length], value_MAC);
    #endif          
                    if(!is_last_step)
                    {
                        int offset = 2<<level;
                        align_MAC(A,  MAC_align_A[i], t);
                        align_MAC(AL, MAC_align_A[i+length], t);
                        write_error_code_to_file_256b(prefix_path_out, A, offset+i);
                        write_error_code_to_file_256b(prefix_path_out, AL, offset+i+length);
                        // write_error_code_to_file_512b(prefix_path_out, A, offset+i);
                        // write_error_code_to_file_512b(prefix_path_out, AL, offset+i+length);
                    }
                    else 
                    {
                        align_MAC(A,  MAC_align_A[i], t);
                        align_MAC(AL, MAC_align_A[i+length], t);
                        write_error_code_to_file_256b(prefix_path_out, A, i);
                        write_error_code_to_file_256b(prefix_path_out, AL, i+length);
                    }

                    vi *= v;
                    conv(vi_ZZ, vi);
                }            
            }));
            start_pos = end_pos;
            end_pos  += length/n_threads;
        }
    }
    else 
    {
        for(int t = 0; t < n_threads; ++t)
        {
            res.push_back(pool.enqueue([this, t, MAC_A0, MAC_A1, MAC_A, MAC_align_A0, MAC_align_A1, MAC_align_A, 
                                        start_pos, end_pos, is_x, path, level, length, is_last_step]() 
            {            
                NTL::ZZ_p::init(PRIME_MODULUS);
                NTL::ZZ_p v  = NTL::power(w, num_blocks/length);
                NTL::ZZ_p vi = power(v, start_pos);
                NTL::ZZ   vi_ZZ;
                conv(vi_ZZ, vi);
    #ifndef ENABLE_KZG
                secp256k1_scalar vi_MAC;
                secp256k1_gej    value_MAC;
    #else 
                bn254_scalar     vi_MAC;
                MAC_Block        value_MAC;
    #endif 
                NTL::ZZ value;
                string prefix_path_in  = path + to_string(level)   + "_";
                string prefix_path_out = path + to_string(level+1) + "_";

                Data_Block A0, A1;
                Data_Block A, AL;
                A.SetLength(NUM_CHUNKS);
                AL.SetLength(NUM_CHUNKS);

                for (int i = start_pos; i < end_pos; ++i)
                {
                    read_error_code_from_file_256b(prefix_path_in, A0, i);
                    read_error_code_from_file_256b(prefix_path_in, A1, i+length);

                    for(int j = 0; j < NUM_CHUNKS; ++j)
                    {
                        value = vi_ZZ * A1[j];
                        A[j]  = (A0[j] + value) % LCM;
                        AL[j] = (A0[j] - value) % LCM;
                    }
                    
                    convert_ZZ_to_scalar(vi_MAC, vi_ZZ);
    #ifndef ENABLE_KZG
                    // Process MAC parts
                    secp256k1_ecmult(&value_MAC, &MAC_A1[i], &vi_MAC, NULL);
                    secp256k1_gej_add_var(&MAC_A[i], &MAC_A0[i], &value_MAC, NULL); 

                    secp256k1_gej_neg(&value_MAC, &value_MAC);
                    secp256k1_gej_add_var(&MAC_A[i+length], &MAC_A0[i], &value_MAC, NULL);

                    // Process alignment parts
                    secp256k1_ecmult(&value_MAC, &MAC_align_A1[i], &vi_MAC, NULL);
                    secp256k1_gej_add_var(&MAC_align_A[i], &MAC_align_A0[i], &value_MAC, NULL); 

                    secp256k1_gej_neg(&value_MAC, &value_MAC);
                    secp256k1_gej_add_var(&MAC_align_A[i+length], &MAC_align_A0[i], &value_MAC, NULL);
    #else 
                    // Process MAC parts
                    memcpy(value_MAC, MAC_A1[i], COMMITMENT_MAC_SIZE);
                    bn254_mult(value_MAC, vi_MAC);

                    memcpy(MAC_A[i], MAC_A0[i], COMMITMENT_MAC_SIZE);
                    bn254_add(MAC_A[i], value_MAC); 

                    bn254_neg(value_MAC);
                    memcpy(MAC_A[i+length], MAC_A0[i], COMMITMENT_MAC_SIZE);
                    bn254_add(MAC_A[i+length], value_MAC);

                    // Process alignment parts
                    memcpy(value_MAC, MAC_align_A1[i], COMMITMENT_MAC_SIZE);
                    bn254_mult(value_MAC, vi_MAC);

                    memcpy(MAC_align_A[i], MAC_align_A0[i], COMMITMENT_MAC_SIZE);
                    bn254_add(MAC_align_A[i], value_MAC); 

                    bn254_neg(value_MAC);
                    memcpy(MAC_align_A[i+length], MAC_align_A0[i], COMMITMENT_MAC_SIZE);
                    bn254_add(MAC_align_A[i+length], value_MAC);
    #endif          
                    if(!is_last_step)
                    {
                        int offset = 2<<level;
                        align_MAC(A,  MAC_align_A[i], t);
                        align_MAC(AL, MAC_align_A[i+length], t);
                        write_error_code_to_file_256b(prefix_path_out, A, offset+i);
                        write_error_code_to_file_256b(prefix_path_out, AL, offset+i+length);
                        // write_error_code_to_file_512b(prefix_path_out, A, offset+i);
                        // write_error_code_to_file_512b(prefix_path_out, AL, offset+i+length);
                    }
                    else 
                    {
                        align_MAC(A,  MAC_align_A[i], t);
                        align_MAC(AL, MAC_align_A[i+length], t);
                        write_error_code_to_file_256b(prefix_path_out, A, i);
                        write_error_code_to_file_256b(prefix_path_out, AL, i+length);
                    }

                    vi *= v;
                    conv(vi_ZZ, vi);
                }            
            }));
            start_pos = end_pos;
            end_pos  += length/n_threads;
        }
    }

    for(auto &v: res) v.get();
    res.clear();
}

void Server::mix(bool is_x, int level)
{
    int length    = 1 << level;
    int n_threads = (length >= MAX_NUM_THREADS_SERVER) ? MAX_NUM_THREADS_SERVER : length;
    
    vector<future<void>> res;
    ThreadPool pool(MAX_NUM_THREADS_SERVER);

    int start_pos = 0;
    int end_pos   = length/n_threads;
    
    Data_Blocks data_A0, data_A1, data_A;
    MAC_Blocks  MAC_A0, MAC_A1, MAC_A;
    MAC_Blocks  MAC_align_A0, MAC_align_A1, MAC_align_A;
    
    if(is_x)
    {
        data_A0      = database_H[level].X;
        data_A1      = &database_H[level].X[length];
        data_A       = &database_H[level+1].X[length<<1];
        MAC_A0       = MAC_commitments_H[level].X;
        MAC_A1       = &MAC_commitments_H[level].X[length];
        MAC_A        = &MAC_commitments_H[level+1].X[length<<1];
        MAC_align_A0 = MAC_alignments_H[level].X;
        MAC_align_A1 = &MAC_alignments_H[level].X[length];
        MAC_align_A  = &MAC_alignments_H[level+1].X[length<<1];
    }
    else 
    {
        data_A0      = database_H[level].Y;
        data_A1      = &database_H[level].Y[length];
        data_A       = &database_H[level+1].Y[length<<1];
        MAC_A0       = MAC_commitments_H[level].Y;
        MAC_A1       = &MAC_commitments_H[level].Y[length];
        MAC_A        = &MAC_commitments_H[level+1].Y[length<<1];
        MAC_align_A0 = MAC_alignments_H[level].Y;
        MAC_align_A1 = &MAC_alignments_H[level].Y[length];
        MAC_align_A  = &MAC_alignments_H[level+1].Y[length<<1];
    }

    for(int t = 0; t < n_threads; ++t)
    {
        res.push_back(pool.enqueue([this, data_A0, data_A1, data_A, MAC_A0, MAC_A1, MAC_A,
                                    MAC_align_A0, MAC_align_A1, MAC_align_A, start_pos, 
                                    end_pos, is_x, level, length]() 
        {            
            NTL::ZZ_p::init(PRIME_MODULUS);
            NTL::ZZ_p v  = NTL::power(w, num_blocks/length);
            NTL::ZZ_p vi = power(v, start_pos);
            NTL::ZZ   vi_ZZ;
            conv(vi_ZZ, vi);
#ifndef ENABLE_KZG
            secp256k1_scalar vi_MAC;
            secp256k1_gej    value_MAC;
#else 
            bn254_scalar     vi_MAC;
            MAC_Block        value_MAC;
#endif 
            NTL::ZZ value;

            for (int i = start_pos; i < end_pos; ++i)
            {
                data_A[i].SetLength(NUM_CHUNKS);
                data_A[i+length].SetLength(NUM_CHUNKS);
                for(int j = 0; j < NUM_CHUNKS; ++j)
                {
                    value               = vi_ZZ * data_A1[i][j];
                    data_A[i][j]        = (data_A0[i][j] + value) % LCM;
                    data_A[i+length][j] = (data_A0[i][j] - value) % LCM;
                }
                
                convert_ZZ_to_scalar(vi_MAC, vi_ZZ);
#ifndef ENABLE_KZG
                // Process MAC parts
                secp256k1_ecmult(&value_MAC, &MAC_A1[i], &vi_MAC, NULL);
                secp256k1_gej_add_var(&MAC_A[i], &MAC_A0[i], &value_MAC, NULL); 

                secp256k1_gej_neg(&value_MAC, &value_MAC);
                secp256k1_gej_add_var(&MAC_A[i+length], &MAC_A0[i], &value_MAC, NULL);

                // Process alignment parts
                secp256k1_ecmult(&value_MAC, &MAC_align_A1[i], &vi_MAC, NULL);
                secp256k1_gej_add_var(&MAC_align_A[i], &MAC_align_A0[i], &value_MAC, NULL); 

                secp256k1_gej_neg(&value_MAC, &value_MAC);
                secp256k1_gej_add_var(&MAC_align_A[i+length], &MAC_align_A0[i], &value_MAC, NULL);
#else 
                // Process MAC parts
                memcpy(value_MAC, MAC_A1[i], COMMITMENT_MAC_SIZE);
                bn254_mult(value_MAC, vi_MAC);

                memcpy(MAC_A[i], MAC_A0[i], COMMITMENT_MAC_SIZE);
                bn254_add(MAC_A[i], value_MAC); 

                bn254_neg(value_MAC);
                memcpy(MAC_A[i+length], MAC_A0[i], COMMITMENT_MAC_SIZE);
                bn254_add(MAC_A[i+length], value_MAC);

                // Process alignment parts
                memcpy(value_MAC, MAC_align_A1[i], COMMITMENT_MAC_SIZE);
                bn254_mult(value_MAC, vi_MAC);

                memcpy(MAC_align_A[i], MAC_align_A0[i], COMMITMENT_MAC_SIZE);
                bn254_add(MAC_align_A[i], value_MAC); 

                bn254_neg(value_MAC);
                memcpy(MAC_align_A[i+length], MAC_align_A0[i], COMMITMENT_MAC_SIZE);
                bn254_add(MAC_align_A[i+length], value_MAC);
#endif          
                vi *= v;
                conv(vi_ZZ, vi);
            }            
        }));
        start_pos = end_pos;
        end_pos  += length/n_threads;
    }
    
    for(auto &v: res) v.get();
    res.clear();
}

void Server::HRebuildX(int level)
{
    bool is_last_step = false;
    for (int i = 0; i < level; ++i)
    {
        if(i == level - 1) is_last_step = true;
        if(i + 1 <= TOP_CACHING_LEVEL)
            mix(true, i);
        else 
            mix(true, "H_X/", i, is_last_step);
    }

    if(level <= TOP_CACHING_LEVEL)
    {
        for(int i = 0; i < (1<<level); ++i)
            database_H[level].X[i] = database_H[level].X[(1<<level)+i];
    }

    for(int i = 0; i < (1<<level); ++i)
    {
        memcpy(&MAC_commitments_H[level].X[i], &MAC_commitments_H[level].X[(1<<level)+i], COMMITMENT_MAC_SIZE);
        memcpy(&MAC_alignments_H[level].X[i], &MAC_alignments_H[level].X[(1<<level)+i], COMMITMENT_MAC_SIZE);
    }
}

void Server::HRebuildY(int level)
{
    bool is_last_step = false;
    for (int i = 0; i < level; ++i)
    {
        if(i == level - 1) is_last_step = true;
        if(i + 1 <= TOP_CACHING_LEVEL)
            mix(false, i);
        else 
            mix(false, "H_Y/", i, is_last_step);
        
        database_H[i].empty        = true;
        MAC_commitments_H[i].empty = true;
        MAC_alignments_H[i].empty  = true;
    }
    
    if(level <= TOP_CACHING_LEVEL)
    {
        for(int i = 0; i < (1<<level); ++i)
            database_H[level].Y[i] = database_H[level].Y[(1<<level)+i];
    }

    for(int i = 0; i < (1<<level); ++i)
    {
        memcpy(&MAC_commitments_H[level].Y[i], &MAC_commitments_H[level].Y[(1<<level)+i], COMMITMENT_MAC_SIZE);
        memcpy(&MAC_alignments_H[level].Y[i], &MAC_alignments_H[level].Y[(1<<level)+i], COMMITMENT_MAC_SIZE);
    }
    
    database_H[level].empty        = false;
    MAC_commitments_H[level].empty = false;
    MAC_alignments_H[level].empty  = false; 
}

int Server::HAdd(Data_Block &data, MAC_Block &MAC)
{
    int level = 0;
    NTL::ZZ_p wt = NTL::power(w, reverse_bits(write_step % num_blocks, height-1));

    NTL::ZZ   wt_ZZ;
    conv(wt_ZZ, wt);
    
    Data_Block data_B2 = data;
    for(int i = 0; i < NUM_CHUNKS; ++i) 
        data_B2[i] *= wt_ZZ;
#ifndef ENABLE_KZG    
    secp256k1_scalar wt_secp256k1;
    convert_ZZ_to_scalar(wt_secp256k1, wt_ZZ);

    MAC_Block MAC_B2;
    secp256k1_ge MAC_prime;    
    secp256k1_ge_set_gej(&MAC_prime, &MAC);
    secp256k1_ecmult_const(&MAC_B2, &MAC_prime, &wt_secp256k1, 256);

    MAC_Block MAC_align;
    MAC_Block MAC_align_B2;
    secp256k1_gej_set_infinity(&MAC_align);
    secp256k1_gej_set_infinity(&MAC_align_B2);
#else 
    bn254_scalar wt_bn254;
    convert_ZZ_to_scalar(wt_bn254, wt_ZZ);

    MAC_Block MAC_B2;
    memcpy(MAC_B2, MAC, COMMITMENT_MAC_SIZE);
    bn254_mult(MAC_B2, wt_bn254);

    MAC_Block MAC_align;
    MAC_Block MAC_align_B2;
    bn254_set_infinity(MAC_align);
    bn254_set_infinity(MAC_align_B2);

#endif 
    align_MAC(data_B2, MAC_align_B2);

    if (database_H[0].empty)
    {
        database_H[0].X[0]         = data;
        database_H[0].Y[0]         = data_B2;
        database_H[0].empty        = false;
#ifndef ENABLE_KZG
        MAC_commitments_H[0].X[0]  = MAC;
        MAC_commitments_H[0].Y[0]  = MAC_B2;
#else 
        memcpy(MAC_commitments_H[0].X[0], MAC, COMMITMENT_MAC_SIZE);
        memcpy(MAC_commitments_H[0].Y[0], MAC_B2, COMMITMENT_MAC_SIZE);
#endif 
        MAC_commitments_H[0].empty = false;
#ifndef ENABLE_KZG
        MAC_alignments_H[0].X[0]   = MAC_align;
        MAC_alignments_H[0].Y[0]   = MAC_align_B2;
#else 
        memcpy(MAC_alignments_H[0].X[0], MAC_align, COMMITMENT_MAC_SIZE);
        memcpy(MAC_alignments_H[0].Y[0], MAC_align_B2, COMMITMENT_MAC_SIZE);
#endif 
        MAC_alignments_H[0].empty  = false;
    }
    else
    {
        level = 1;
        while (!database_H[level].empty)
            level++;

        database_H[0].X[1]         = data;
        database_H[0].Y[1]         = data_B2;
#ifndef ENABLE_KZG
        MAC_commitments_H[0].X[1]  = MAC;
        MAC_commitments_H[0].Y[1]  = MAC_B2;
#else 
        memcpy(MAC_commitments_H[0].X[1], MAC, COMMITMENT_MAC_SIZE);
        memcpy(MAC_commitments_H[0].Y[1], MAC_B2, COMMITMENT_MAC_SIZE);
#endif 
#ifndef ENABLE_KZG
        MAC_alignments_H[0].X[1]   = MAC_align;
        MAC_alignments_H[0].Y[1]   = MAC_align_B2;
#else 
        memcpy(MAC_alignments_H[0].X[1], MAC_align, COMMITMENT_MAC_SIZE);
        memcpy(MAC_alignments_H[0].Y[1], MAC_align_B2, COMMITMENT_MAC_SIZE);
#endif 
        HRebuildX(level);
        HRebuildY(level);
    }

    return level;
}

void Server::CRebuild()
{
    if(height - 1 > TOP_CACHING_LEVEL)
        CRebuild_No_Cached();
    else 
        CRebuild_Cached();
}

void Server::CRebuild_Cached()
{
    // Add blocks from U to rebuild C (H at level k+1) 
    // Clear H before using it to rebuild C
    clear_H_data(height-1);
    clear_H_MAC(height-1);

    NTL::ZZ_p wt = NTL::power(w, reverse_bits(write_step % num_blocks, height-1));
    NTL::ZZ   wt_ZZ;
    conv(wt_ZZ, wt);

#ifndef ENABLE_KZG
    secp256k1_scalar wt_MAC;
    convert_ZZ_to_scalar(wt_MAC, wt_ZZ);
#else 
    bn254_scalar wt_MAC;
    convert_ZZ_to_scalar(wt_MAC, wt_ZZ);
#endif
    ThreadPool pool(MAX_NUM_THREADS_SERVER);
    vector<future<void>> res;

    int start_pos = 0;
    int end_pos   = num_blocks/MAX_NUM_THREADS_SERVER;

    // Copy data from raw buffer U
    for(int t = 0; t < MAX_NUM_THREADS_SERVER; ++t)
    {
        res.push_back(pool.enqueue([this, start_pos, end_pos, &wt_ZZ, &wt_MAC]() 
        {
            for(int i = start_pos; i < end_pos; ++i)
            {
                string file_path = "U/" + to_string(i);
                read_data_block_from_file(file_path, database_H[height-1].X[i]);
                database_H[height-1].Y[i].SetLength(NUM_CHUNKS);
                for(int j = 0; j < NUM_CHUNKS; ++j)
                    database_H[height-1].Y[i][j] = database_H[height-1].X[i][j] * wt_ZZ;
#ifndef ENABLE_KZG
                memcpy(&MAC_commitments_H[height-1].X[i], &MAC_commitments_U[i], COMMITMENT_MAC_SIZE);
                secp256k1_ecmult(&MAC_commitments_H[height-1].Y[i], &MAC_commitments_U[i], &wt_MAC, NULL);

                secp256k1_gej_set_infinity(&MAC_alignments_H[height-1].X[i]);
                secp256k1_gej_set_infinity(&MAC_alignments_H[height-1].Y[i]);
#else 
                memcpy(MAC_commitments_H[height-1].X[i], MAC_commitments_U[i], COMMITMENT_MAC_SIZE);
                memcpy(MAC_commitments_H[height-1].Y[i], MAC_commitments_U[i], COMMITMENT_MAC_SIZE);
                bn254_mult(MAC_commitments_H[height-1].Y[i], wt_MAC);

                bn254_set_infinity(MAC_alignments_H[height-1].X[i]);
                bn254_set_infinity(MAC_alignments_H[height-1].Y[i]);
#endif
            }
        }));
        start_pos = end_pos;
        end_pos  += num_blocks/MAX_NUM_THREADS_SERVER;
    }
    for(auto &v: res) v.get(); res.clear();
    
    // Compute FFT-based erasure code C based on fresh data U
    // X Part
    cout << "Rebuilding X Part.." << endl;

    for(int s = 1; s < height; ++s)
    {
        cout << s << ".." << flush;
        int m  = 1 << s;
        int m2 = m >> 1;
        NTL::ZZ_p v = NTL::power(w, num_blocks/m2);
        NTL::ZZ_p vi(1);
        NTL::ZZ   vi_ZZ(1);
#ifndef ENABLE_KZG
        secp256k1_scalar vi_MAC;
#else 
        bn254_scalar vi_MAC;
#endif  
        ThreadPool pool(MAX_NUM_THREADS_SERVER);
        vector<future<void>> res;

        if(m2 < MAX_NUM_THREADS_SERVER)
        {
            for(int j = 0; j < m2; ++j)
            {
                convert_ZZ_to_scalar(vi_MAC, vi_ZZ);
                int range_per_thread = m * ceil((num_blocks-j+1)/m/MAX_NUM_THREADS_SERVER);
                int start_pos = j;
                int end_pos   = j + range_per_thread;
                for(int t = 0; t < MAX_NUM_THREADS_SERVER; ++t)
                {
                    res.push_back(pool.enqueue([this, start_pos, end_pos, m, m2, &vi_ZZ, &vi_MAC]() 
                    {
                        NTL::ZZ      u, t;
                        MAC_Block    um, tm;
                        
                        for(int k = start_pos; k < end_pos; k += m)
                        {
                            // Process DATA parts
                            for(int p = 0; p < NUM_CHUNKS; ++p)
                            {
                                t = vi_ZZ * database_H[height-1].X[k+m2][p];
                                u = database_H[height-1].X[k][p];
                                database_H[height-1].X[k][p]      = (u + t) % LCM;
                                database_H[height-1].X[k + m2][p] = (u - t) % LCM;
                            }

                            // Process MAC parts
#ifndef ENABLE_KZG
                            secp256k1_ecmult(&tm, &MAC_commitments_H[height-1].X[k+m2], &vi_MAC, NULL);
                            memcpy(&um, &MAC_commitments_H[height-1].X[k], COMMITMENT_MAC_SIZE);

                            secp256k1_gej_add_var(&MAC_commitments_H[height-1].X[k], &um, &tm, NULL); 

                            secp256k1_gej_neg(&tm, &tm);
                            secp256k1_gej_add_var(&MAC_commitments_H[height-1].X[k+m2], &um, &tm, NULL);
#else 
                            memcpy(tm, MAC_commitments_H[height-1].X[k+m2], COMMITMENT_MAC_SIZE);
                            bn254_mult(tm, vi_MAC);
                            memcpy(um, MAC_commitments_H[height-1].X[k], COMMITMENT_MAC_SIZE);

                            bn254_add(MAC_commitments_H[height-1].X[k], tm); 

                            bn254_neg(tm);
                            memcpy(MAC_commitments_H[height-1].X[k+m2], um, COMMITMENT_MAC_SIZE);
                            bn254_add(MAC_commitments_H[height-1].X[k+m2], tm);
#endif
                        }
                    }));
                    start_pos = end_pos;
                    if(t == MAX_NUM_THREADS_SERVER-2)
                        end_pos  = num_blocks;
                    else 
                        end_pos += range_per_thread;
                }
                for(auto &v: res) v.get(); res.clear();
                vi *= v;
                conv(vi_ZZ, vi);
            }
        }
        else 
        {
            int start_pos = 0;
            int end_pos   = m2/MAX_NUM_THREADS_SERVER;
            for(int t = 0; t < MAX_NUM_THREADS_SERVER; ++t)
            {
                res.push_back(pool.enqueue([this, start_pos, end_pos, m, m2, &v]() 
                {
                    NTL::ZZ_p::init(PRIME_MODULUS);
                    NTL::ZZ      u, t;
                    MAC_Block    um, tm;
                    NTL::ZZ_p    vi = NTL::power(v, start_pos);
                    NTL::ZZ      vi_ZZ;
                    conv(vi_ZZ, vi);
#ifndef ENABLE_KZG
                    secp256k1_scalar vi_MAC;
#else 
                    bn254_scalar vi_MAC;
#endif  
                    for(int j = start_pos; j < end_pos; ++j)
                    {
                        convert_ZZ_to_scalar(vi_MAC, vi_ZZ);

                        for(int k = j; k < num_blocks; k += m)
                        {
                            // Process DATA parts
                            for(int p = 0; p < NUM_CHUNKS; ++p)
                            {
                                t = vi_ZZ * database_H[height-1].X[k+m2][p];
                                u = database_H[height-1].X[k][p];
                                database_H[height-1].X[k][p]      = (u + t) % LCM;
                                database_H[height-1].X[k + m2][p] = (u - t) % LCM;
                            }

                            // Process MAC parts
#ifndef ENABLE_KZG
                            secp256k1_ecmult(&tm, &MAC_commitments_H[height-1].X[k+m2], &vi_MAC, NULL);
                            memcpy(&um, &MAC_commitments_H[height-1].X[k], COMMITMENT_MAC_SIZE);

                            secp256k1_gej_add_var(&MAC_commitments_H[height-1].X[k], &um, &tm, NULL); 

                            secp256k1_gej_neg(&tm, &tm);
                            secp256k1_gej_add_var(&MAC_commitments_H[height-1].X[k+m2], &um, &tm, NULL);
#else 
                            memcpy(tm, MAC_commitments_H[height-1].X[k+m2], COMMITMENT_MAC_SIZE);
                            bn254_mult(tm, vi_MAC);
                            memcpy(um, MAC_commitments_H[height-1].X[k], COMMITMENT_MAC_SIZE);

                            bn254_add(MAC_commitments_H[height-1].X[k], tm); 

                            bn254_neg(tm);
                            memcpy(MAC_commitments_H[height-1].X[k+m2], um, COMMITMENT_MAC_SIZE);
                            bn254_add(MAC_commitments_H[height-1].X[k+m2], tm);
#endif
                        }
                        vi *= v;
                        conv(vi_ZZ, vi);
                    }
                }));
                start_pos = end_pos;
                end_pos  += m2/MAX_NUM_THREADS_SERVER;
            }
            for(auto &v: res) v.get(); res.clear();
        }
    }

    // Y Part
    cout << endl << "Rebuilding Y Part.." << endl;
    for(int s = 1; s < height; ++s)
    {
        cout << s << ".." << flush;
        int m  = 1 << s;
        int m2 = m >> 1;
        NTL::ZZ_p v  = NTL::power(w, num_blocks/m2);
        NTL::ZZ_p vi(1);
        NTL::ZZ   vi_ZZ(1); 
#ifndef ENABLE_KZG
        secp256k1_scalar vi_MAC;
#else 
        bn254_scalar vi_MAC;
#endif   

        ThreadPool pool(MAX_NUM_THREADS_SERVER);
        vector<future<void>> res;

        if(m2 < MAX_NUM_THREADS_SERVER)
        {
            for(int j = 0; j < m2; ++j)
            {
                convert_ZZ_to_scalar(vi_MAC, vi_ZZ);
                int range_per_thread = m * ceil((num_blocks-j+1)/m/MAX_NUM_THREADS_SERVER);
                int start_pos = j;
                int end_pos   = j + range_per_thread;
                for(int t = 0; t < MAX_NUM_THREADS_SERVER; ++t)
                {
                    res.push_back(pool.enqueue([this, start_pos, end_pos, m, m2, &vi_ZZ, &vi_MAC]() 
                    {
                        NTL::ZZ      u, t;
                        MAC_Block    um, tm;
                        
                        for(int k = start_pos; k < end_pos; k += m)
                        {
                            // Process DATA parts
                            for(int p = 0; p < NUM_CHUNKS; ++p)
                            {
                                t = vi_ZZ * database_H[height-1].Y[k+m2][p];
                                u = database_H[height-1].Y[k][p];
                                database_H[height-1].Y[k][p]      = (u + t) % LCM;
                                database_H[height-1].Y[k + m2][p] = (u - t) % LCM;
                            }
#ifndef ENABLE_KZG
                            // Process MAC parts
                            secp256k1_ecmult(&tm, &MAC_commitments_H[height-1].Y[k+m2], &vi_MAC, NULL);
                            memcpy(&um, &MAC_commitments_H[height-1].Y[k], COMMITMENT_MAC_SIZE);

                            secp256k1_gej_add_var(&MAC_commitments_H[height-1].Y[k], &um, &tm, NULL); 

                            secp256k1_gej_neg(&tm, &tm);
                            secp256k1_gej_add_var(&MAC_commitments_H[height-1].Y[k+m2], &um, &tm, NULL);
    #else 
                            memcpy(tm, MAC_commitments_H[height-1].Y[k+m2], COMMITMENT_MAC_SIZE);
                            bn254_mult(tm, vi_MAC);
                            memcpy(um, MAC_commitments_H[height-1].Y[k], COMMITMENT_MAC_SIZE);

                            bn254_add(MAC_commitments_H[height-1].Y[k], tm); 

                            bn254_neg(tm);
                            memcpy(MAC_commitments_H[height-1].Y[k+m2], um, COMMITMENT_MAC_SIZE);
                            bn254_add(MAC_commitments_H[height-1].Y[k+m2], tm);
#endif 
                        }
                    }));
                    start_pos = end_pos;
                    if(t == MAX_NUM_THREADS_SERVER-2)
                        end_pos  = num_blocks;
                    else 
                        end_pos += range_per_thread;
                }
                for(auto &v: res) v.get(); res.clear();
                vi *= v;
                conv(vi_ZZ, vi);
            }
        }
        else 
        {
            int start_pos = 0;
            int end_pos   = m2/MAX_NUM_THREADS_SERVER;
            for(int t = 0; t < MAX_NUM_THREADS_SERVER; ++t)
            {
                res.push_back(pool.enqueue([this, start_pos, end_pos, m, m2, &v]() 
                {
                    NTL::ZZ_p::init(PRIME_MODULUS);
                    NTL::ZZ      u, t;
                    MAC_Block    um, tm;
                    NTL::ZZ_p    vi = NTL::power(v, start_pos);
                    NTL::ZZ      vi_ZZ;
                    conv(vi_ZZ, vi);
#ifndef ENABLE_KZG
                    secp256k1_scalar vi_MAC;
#else 
                    bn254_scalar vi_MAC;
#endif  
                    for(int j = start_pos; j < end_pos; ++j)
                    {
                        convert_ZZ_to_scalar(vi_MAC, vi_ZZ);

                        for(int k = j; k < num_blocks; k += m)
                        {
                            // Process DATA parts
                            for(int p = 0; p < NUM_CHUNKS; ++p)
                            {
                                t = vi_ZZ * database_H[height-1].Y[k+m2][p];
                                u = database_H[height-1].Y[k][p];
                                database_H[height-1].Y[k][p]      = (u + t) % LCM;
                                database_H[height-1].Y[k + m2][p] = (u - t) % LCM;
                            }

                            // Process MAC parts
#ifndef ENABLE_KZG
                            secp256k1_ecmult(&tm, &MAC_commitments_H[height-1].Y[k+m2], &vi_MAC, NULL);
                            memcpy(&um, &MAC_commitments_H[height-1].Y[k], COMMITMENT_MAC_SIZE);

                            secp256k1_gej_add_var(&MAC_commitments_H[height-1].Y[k], &um, &tm, NULL); 

                            secp256k1_gej_neg(&tm, &tm);
                            secp256k1_gej_add_var(&MAC_commitments_H[height-1].Y[k+m2], &um, &tm, NULL);
#else 
                            memcpy(tm, MAC_commitments_H[height-1].Y[k+m2], COMMITMENT_MAC_SIZE);
                            bn254_mult(tm, vi_MAC);
                            memcpy(um, MAC_commitments_H[height-1].Y[k], COMMITMENT_MAC_SIZE);

                            bn254_add(MAC_commitments_H[height-1].Y[k], tm); 

                            bn254_neg(tm);
                            memcpy(MAC_commitments_H[height-1].Y[k+m2], um, COMMITMENT_MAC_SIZE);
                            bn254_add(MAC_commitments_H[height-1].Y[k+m2], tm);
#endif
                        }
                        vi *= v;
                        conv(vi_ZZ, vi);
                    }
                }));
                start_pos = end_pos;
                end_pos  += m2/MAX_NUM_THREADS_SERVER;
            }
            for(auto &v: res) v.get(); res.clear();
        }
    }

    cout << endl; 
}

void Server::CRebuild_No_Cached()
{
    // Add blocks from U to rebuild C (H at level k+1) 
    // Clear H before using it to rebuild C
    clear_H_data(height-1);
    clear_H_MAC(height-1);

    NTL::ZZ_p wt = NTL::power(w, reverse_bits(write_step % num_blocks, height-1));
    NTL::ZZ   wt_ZZ;
    conv(wt_ZZ, wt);

#ifndef ENABLE_KZG
    secp256k1_scalar wt_MAC;
    convert_ZZ_to_scalar(wt_MAC, wt_ZZ);
#else 
    bn254_scalar wt_MAC;
    convert_ZZ_to_scalar(wt_MAC, wt_ZZ);
#endif
    ThreadPool pool(MAX_NUM_THREADS_SERVER);
    vector<future<void>> res;

    int start_pos = 0;
    int end_pos   = num_blocks/MAX_NUM_THREADS_SERVER;
    
    // Copy data from raw buffer U
    for(int t = 0; t < MAX_NUM_THREADS_SERVER; ++t)
    {
        res.push_back(pool.enqueue([this, start_pos, end_pos, &wt_ZZ, &wt_MAC]() 
        {
            Data_Block X, Y;
            string prefix_path_x = "H_X/" + to_string(height-1) + "_";
            string prefix_path_y = "H_Y/" + to_string(height-1) + "_";

            for(int i = start_pos; i < end_pos; ++i)
            {
                string file_path = "U/" + to_string(i);
                read_data_block_from_file(file_path, X);
                Y.SetLength(NUM_CHUNKS);
                for(int j = 0; j < NUM_CHUNKS; ++j)
                    Y[j] = X[j] * wt_ZZ;
                write_error_code_to_file_512b(prefix_path_x, X, i);
                write_error_code_to_file_512b(prefix_path_y, Y, i);

#ifndef ENABLE_KZG
                memcpy(&MAC_commitments_H[height-1].X[i], &MAC_commitments_U[i], COMMITMENT_MAC_SIZE);
                secp256k1_ecmult(&MAC_commitments_H[height-1].Y[i], &MAC_commitments_U[i], &wt_MAC, NULL);

                secp256k1_gej_set_infinity(&MAC_alignments_H[height-1].X[i]);
                secp256k1_gej_set_infinity(&MAC_alignments_H[height-1].Y[i]);
#else 
                memcpy(MAC_commitments_H[height-1].X[i], MAC_commitments_U[i], COMMITMENT_MAC_SIZE);
                memcpy(MAC_commitments_H[height-1].Y[i], MAC_commitments_U[i], COMMITMENT_MAC_SIZE);
                bn254_mult(MAC_commitments_H[height-1].Y[i], wt_MAC);

                bn254_set_infinity(MAC_alignments_H[height-1].X[i]);
                bn254_set_infinity(MAC_alignments_H[height-1].Y[i]);
#endif
            }
        }));
        start_pos = end_pos;
        end_pos  += num_blocks/MAX_NUM_THREADS_SERVER;
    }
    for(auto &v: res) v.get(); res.clear();
    
    // Compute FFT-based erasure code C based on fresh data U
    // X Part
    cout << "Rebuilding X Part.." << endl;

    for(int s = 1; s < height; ++s)
    {
        cout << s << ".." << flush;
        int m  = 1 << s;
        int m2 = m >> 1;
        NTL::ZZ_p v = NTL::power(w, num_blocks/m2);
        NTL::ZZ_p vi(1);
        NTL::ZZ   vi_ZZ(1);
#ifndef ENABLE_KZG
        secp256k1_scalar vi_MAC;
#else 
        bn254_scalar vi_MAC;
#endif  
        ThreadPool pool(MAX_NUM_THREADS_SERVER);
        vector<future<void>> res;

        if(m2 < MAX_NUM_THREADS_SERVER)
        {
            for(int j = 0; j < m2; ++j)
            {
                convert_ZZ_to_scalar(vi_MAC, vi_ZZ);
                int range_per_thread = m * ceil((num_blocks-j+1)/m/MAX_NUM_THREADS_SERVER);
                int start_pos = j;
                int end_pos   = j + range_per_thread;
                for(int thr = 0; thr < MAX_NUM_THREADS_SERVER; ++thr)
                {
                    res.push_back(pool.enqueue([this, thr, s, start_pos, end_pos, m, m2, &vi_ZZ, &vi_MAC]() 
                    {
                        NTL::ZZ       u, t;
                        NTL::vec_ZZ   Xk, Xkm2;
                        MAC_Block     um, tm;
                        string        prefix_path = "H_X/" + to_string(height-1) + "_";

                        for(int k = start_pos; k < end_pos; k += m)
                        {
                            read_error_code_from_file_512b(prefix_path, Xk, k);
                            read_error_code_from_file_512b(prefix_path, Xkm2, k + m2);

                            // Process DATA parts
                            for(int p = 0; p < NUM_CHUNKS; ++p)
                            {
                                t       = vi_ZZ * Xkm2[p];
                                u       = Xk[p];
                                Xk[p]   = (u + t) % LCM;
                                Xkm2[p] = (u - t) % LCM;
                            }
                            
                            // Process MAC parts
#ifndef ENABLE_KZG
                            secp256k1_ecmult(&tm, &MAC_commitments_H[height-1].X[k+m2], &vi_MAC, NULL);
                            memcpy(&um, &MAC_commitments_H[height-1].X[k], COMMITMENT_MAC_SIZE);

                            secp256k1_gej_add_var(&MAC_commitments_H[height-1].X[k], &um, &tm, NULL); 

                            secp256k1_gej_neg(&tm, &tm);
                            secp256k1_gej_add_var(&MAC_commitments_H[height-1].X[k+m2], &um, &tm, NULL);
#else 
                            memcpy(tm, MAC_commitments_H[height-1].X[k+m2], COMMITMENT_MAC_SIZE);
                            bn254_mult(tm, vi_MAC);
                            memcpy(um, MAC_commitments_H[height-1].X[k], COMMITMENT_MAC_SIZE);

                            bn254_add(MAC_commitments_H[height-1].X[k], tm); 

                            bn254_neg(tm);
                            memcpy(MAC_commitments_H[height-1].X[k+m2], um, COMMITMENT_MAC_SIZE);
                            bn254_add(MAC_commitments_H[height-1].X[k+m2], tm);
#endif
                            if(s < height-1)
                            {
                                write_error_code_to_file_512b(prefix_path, Xk, k);
                                write_error_code_to_file_512b(prefix_path, Xkm2, k + m2);
                            }
                            else 
                            {
                                align_MAC(Xk, MAC_alignments_H[height-1].X[k], thr);
                                align_MAC(Xkm2, MAC_alignments_H[height-1].X[k+m2], thr);
                                write_error_code_to_file_256b(prefix_path, Xk, k);
                                write_error_code_to_file_256b(prefix_path, Xkm2, k + m2);
                            }
                        }
                    }));
                    start_pos = end_pos;
                    if(thr == MAX_NUM_THREADS_SERVER-2)
                        end_pos  = num_blocks;
                    else 
                        end_pos += range_per_thread;
                }
                for(auto &v: res) v.get(); res.clear();
                vi *= v;
                conv(vi_ZZ, vi);
            }
        }
        else 
        {
            int start_pos = 0;
            int end_pos   = m2/MAX_NUM_THREADS_SERVER;
            for(int thr = 0; thr < MAX_NUM_THREADS_SERVER; ++thr)
            {
                res.push_back(pool.enqueue([this, thr, s, start_pos, end_pos, m, m2, &v]() 
                {
                    NTL::ZZ_p::init(PRIME_MODULUS);
                    NTL::ZZ      u, t;
                    NTL::vec_ZZ  Xk, Xkm2;
                    MAC_Block    um, tm;
                    string       prefix_path = "H_X/" + to_string(height-1) + "_";
                    NTL::ZZ_p    vi = NTL::power(v, start_pos);
                    NTL::ZZ      vi_ZZ;
                    conv(vi_ZZ, vi);
#ifndef ENABLE_KZG
                    secp256k1_scalar vi_MAC;
#else 
                    bn254_scalar vi_MAC;
#endif  
                    for(int j = start_pos; j < end_pos; ++j)
                    {
                        convert_ZZ_to_scalar(vi_MAC, vi_ZZ);

                        for(int k = j; k < num_blocks; k += m)
                        {
                            // Process DATA parts
                            read_error_code_from_file_512b(prefix_path, Xk, k);
                            read_error_code_from_file_512b(prefix_path, Xkm2, k + m2);

                            for(int p = 0; p < NUM_CHUNKS; ++p)
                            {
                                t       = vi_ZZ * Xkm2[p];
                                u       = Xk[p];
                                Xk[p]   = (u + t) % LCM;
                                Xkm2[p] = (u - t) % LCM;
                            }

                            // Process MAC parts
#ifndef ENABLE_KZG
                            secp256k1_ecmult(&tm, &MAC_commitments_H[height-1].X[k+m2], &vi_MAC, NULL);
                            memcpy(&um, &MAC_commitments_H[height-1].X[k], COMMITMENT_MAC_SIZE);

                            secp256k1_gej_add_var(&MAC_commitments_H[height-1].X[k], &um, &tm, NULL); 

                            secp256k1_gej_neg(&tm, &tm);
                            secp256k1_gej_add_var(&MAC_commitments_H[height-1].X[k+m2], &um, &tm, NULL);
#else 
                            memcpy(tm, MAC_commitments_H[height-1].X[k+m2], COMMITMENT_MAC_SIZE);
                            bn254_mult(tm, vi_MAC);
                            memcpy(um, MAC_commitments_H[height-1].X[k], COMMITMENT_MAC_SIZE);

                            bn254_add(MAC_commitments_H[height-1].X[k], tm); 

                            bn254_neg(tm);
                            memcpy(MAC_commitments_H[height-1].X[k+m2], um, COMMITMENT_MAC_SIZE);
                            bn254_add(MAC_commitments_H[height-1].X[k+m2], tm);
#endif
                            if(s < height-1)
                            {
                                write_error_code_to_file_512b(prefix_path, Xk, k);
                                write_error_code_to_file_512b(prefix_path, Xkm2, k + m2);
                            }
                            else 
                            {
                                align_MAC(Xk, MAC_alignments_H[height-1].X[k], thr);
                                align_MAC(Xkm2, MAC_alignments_H[height-1].X[k+m2], thr);
                                write_error_code_to_file_256b(prefix_path, Xk, k);
                                write_error_code_to_file_256b(prefix_path, Xkm2, k + m2);
                            }
                        }
                        vi *= v;
                        conv(vi_ZZ, vi);
                    }
                }));
                start_pos = end_pos;
                end_pos  += m2/MAX_NUM_THREADS_SERVER;
            }
            for(auto &v: res) v.get(); res.clear();
        }
    }

    // Y Part
    cout << endl << "Rebuilding Y Part.." << endl;
    for(int s = 1; s < height; ++s)
    {
        cout << s << ".." << flush;
        int m  = 1 << s;
        int m2 = m >> 1;
        NTL::ZZ_p v  = NTL::power(w, num_blocks/m2);
        NTL::ZZ_p vi(1);
        NTL::ZZ   vi_ZZ(1); 
#ifndef ENABLE_KZG
        secp256k1_scalar vi_MAC;
#else 
        bn254_scalar vi_MAC;
#endif   

        ThreadPool pool(MAX_NUM_THREADS_SERVER);
        vector<future<void>> res;

        if(m2 < MAX_NUM_THREADS_SERVER)
        {
            for(int j = 0; j < m2; ++j)
            {
                convert_ZZ_to_scalar(vi_MAC, vi_ZZ);
                int range_per_thread = m * ceil((num_blocks-j+1)/m/MAX_NUM_THREADS_SERVER);
                int start_pos = j;
                int end_pos   = j + range_per_thread;
                for(int thr = 0; thr < MAX_NUM_THREADS_SERVER; ++thr)
                {
                    res.push_back(pool.enqueue([this, thr, s, start_pos, end_pos, m, m2, &vi_ZZ, &vi_MAC]() 
                    {
                        NTL::ZZ      u, t;
                        NTL::vec_ZZ  Yk, Ykm2;
                        MAC_Block    um, tm;
                        string       prefix_path = "H_Y/" + to_string(height-1) + "_";
                        
                        for(int k = start_pos; k < end_pos; k += m)
                        {
                            // Process DATA parts
                            read_error_code_from_file_512b(prefix_path, Yk, k);
                            read_error_code_from_file_512b(prefix_path, Ykm2, k + m2);

                            for(int p = 0; p < NUM_CHUNKS; ++p)
                            {
                                t       = vi_ZZ * Ykm2[p];
                                u       = Yk[p];
                                Yk[p]   = (u + t) % LCM;
                                Ykm2[p] = (u - t) % LCM;
                            }
#ifndef ENABLE_KZG
                            // Process MAC parts
                            secp256k1_ecmult(&tm, &MAC_commitments_H[height-1].Y[k+m2], &vi_MAC, NULL);
                            memcpy(&um, &MAC_commitments_H[height-1].Y[k], COMMITMENT_MAC_SIZE);

                            secp256k1_gej_add_var(&MAC_commitments_H[height-1].Y[k], &um, &tm, NULL); 

                            secp256k1_gej_neg(&tm, &tm);
                            secp256k1_gej_add_var(&MAC_commitments_H[height-1].Y[k+m2], &um, &tm, NULL);
    #else 
                            memcpy(tm, MAC_commitments_H[height-1].Y[k+m2], COMMITMENT_MAC_SIZE);
                            bn254_mult(tm, vi_MAC);
                            memcpy(um, MAC_commitments_H[height-1].Y[k], COMMITMENT_MAC_SIZE);

                            bn254_add(MAC_commitments_H[height-1].Y[k], tm); 

                            bn254_neg(tm);
                            memcpy(MAC_commitments_H[height-1].Y[k+m2], um, COMMITMENT_MAC_SIZE);
                            bn254_add(MAC_commitments_H[height-1].Y[k+m2], tm);
#endif 
                            if(s < height-1)
                            {
                                write_error_code_to_file_512b(prefix_path, Yk, k);
                                write_error_code_to_file_512b(prefix_path, Ykm2, k + m2);
                            }
                            else 
                            {
                                align_MAC(Yk, MAC_alignments_H[height-1].Y[k], thr);
                                align_MAC(Ykm2, MAC_alignments_H[height-1].Y[k+m2], thr);
                                write_error_code_to_file_256b(prefix_path, Yk, k);
                                write_error_code_to_file_256b(prefix_path, Ykm2, k + m2);
                            }
                        }
                    }));
                    start_pos = end_pos;
                    if(thr == MAX_NUM_THREADS_SERVER-2)
                        end_pos  = num_blocks;
                    else 
                        end_pos += range_per_thread;
                }
                for(auto &v: res) v.get(); res.clear();
                vi *= v;
                conv(vi_ZZ, vi);
            }
        }
        else 
        {
            int start_pos = 0;
            int end_pos   = m2/MAX_NUM_THREADS_SERVER;
            for(int thr = 0; thr < MAX_NUM_THREADS_SERVER; ++thr)
            {
                res.push_back(pool.enqueue([this, thr, s, start_pos, end_pos, m, m2, &v]() 
                {
                    NTL::ZZ_p::init(PRIME_MODULUS);
                    NTL::ZZ      u, t;
                    NTL::vec_ZZ  Yk, Ykm2;
                    MAC_Block    um, tm;
                    string       prefix_path = "H_Y/" + to_string(height-1) + "_";
                    NTL::ZZ_p    vi = NTL::power(v, start_pos);
                    NTL::ZZ      vi_ZZ;
                    conv(vi_ZZ, vi);
#ifndef ENABLE_KZG
                    secp256k1_scalar vi_MAC;
#else 
                    bn254_scalar vi_MAC;
#endif  
                    for(int j = start_pos; j < end_pos; ++j)
                    {
                        convert_ZZ_to_scalar(vi_MAC, vi_ZZ);

                        for(int k = j; k < num_blocks; k += m)
                        {
                            // Process DATA parts
                            read_error_code_from_file_512b(prefix_path, Yk, k);
                            read_error_code_from_file_512b(prefix_path, Ykm2, k + m2);

                            for(int p = 0; p < NUM_CHUNKS; ++p)
                            {
                                t       = vi_ZZ * Ykm2[p];
                                u       = Yk[p];
                                Yk[p]   = (u + t) % LCM;
                                Ykm2[p] = (u - t) % LCM;
                            }

                            // Process MAC parts
#ifndef ENABLE_KZG
                            secp256k1_ecmult(&tm, &MAC_commitments_H[height-1].Y[k+m2], &vi_MAC, NULL);
                            memcpy(&um, &MAC_commitments_H[height-1].Y[k], COMMITMENT_MAC_SIZE);

                            secp256k1_gej_add_var(&MAC_commitments_H[height-1].Y[k], &um, &tm, NULL); 

                            secp256k1_gej_neg(&tm, &tm);
                            secp256k1_gej_add_var(&MAC_commitments_H[height-1].Y[k+m2], &um, &tm, NULL);
#else 
                            memcpy(tm, MAC_commitments_H[height-1].Y[k+m2], COMMITMENT_MAC_SIZE);
                            bn254_mult(tm, vi_MAC);
                            memcpy(um, MAC_commitments_H[height-1].Y[k], COMMITMENT_MAC_SIZE);

                            bn254_add(MAC_commitments_H[height-1].Y[k], tm); 

                            bn254_neg(tm);
                            memcpy(MAC_commitments_H[height-1].Y[k+m2], um, COMMITMENT_MAC_SIZE);
                            bn254_add(MAC_commitments_H[height-1].Y[k+m2], tm);
#endif
                            if(s < height-1)
                            {
                                write_error_code_to_file_512b(prefix_path, Yk, k);
                                write_error_code_to_file_512b(prefix_path, Ykm2, k + m2);
                            }
                            else 
                            {
                                align_MAC(Yk, MAC_alignments_H[height-1].Y[k], thr);
                                align_MAC(Ykm2, MAC_alignments_H[height-1].Y[k+m2], thr);
                                write_error_code_to_file_256b(prefix_path, Yk, k);
                                write_error_code_to_file_256b(prefix_path, Ykm2, k + m2);
                            }
                        }
                        vi *= v;
                        conv(vi_ZZ, vi);
                    }
                }));
                start_pos = end_pos;
                end_pos  += m2/MAX_NUM_THREADS_SERVER;
            }
            for(auto &v: res) v.get(); res.clear();
        }
    }
    cout << endl; 
}

void Server::clear_H_data(int until_level)
{
    for (int i = 0; i < until_level; ++i) 
    {
        if(!database_H[i].empty)
            database_H[i].empty = true;
    }
}

void Server::clear_H_MAC(int until_level)
{
    for (int i = 0; i < until_level; ++i) 
    {
        if(!MAC_commitments_H[i].empty)
        {
            MAC_commitments_H[i].empty = true;
            MAC_alignments_H[i].empty  = true;
        }
    }
}

#ifndef ENABLE_KZG
void Server::inner_product_prove(NTL::vec_ZZ &a, NTL::vec_ZZ &b, uint8_t *proof)
{
    size_t k;
    size_t half_width;
    uint8_t *proof_ptr = proof;
    unsigned char random_str[] = "hash of P, c, etc. all that jazz";

    NTL::ZZ inner_product = (a * b) % GROUP_ORDER;
    convert_ZZ_to_arr((uint32_t*)proof, inner_product);
    proof_ptr += 32;
    
    secp256k1_scalar  c;
    secp256k1_gej     uc;
    secp256k1_gej     L;
    secp256k1_gej     R;
    secp256k1_ge      temp;
    
    NTL::vec_ZZ x_values;
    NTL::ZZ     v;

    x_values.SetLength(NUM_CHUNKS);
    for(int i = 0; i < NUM_CHUNKS; ++i)
        x_values[i] = 1;
    
    int count = 0;
    vector<future<void>> res;

    secp256k1_sha256 sha256;
    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, random_str, 32);
    secp256k1_sha256_write(&sha256, proof, 32);
    secp256k1_sha256_finalize(&sha256, random_str);

    NTL::ZZ x;
    NTL::ZZ inv_x;
    NTL::ZZ_p random_ZZ_p;
    NTL::ZZ_p inv_random_ZZ_p;
    ThreadPool pool(MAX_NUM_THREADS_SERVER);

    for(half_width = NUM_CHUNKS/2, k = 1; half_width > 1; half_width>>=1, k<<=1)
    {
        convert_arr_to_ZZ_p(random_ZZ_p, (uint32_t*)random_str);
        NTL::inv(inv_random_ZZ_p, random_ZZ_p);
        conv(x, random_ZZ_p);
        conv(inv_x, inv_random_ZZ_p); 

        // Compute cL, cR
        NTL::ZZ cL(0);
        for(int i = 0; i < half_width; ++i)
            cL += a[i] * b[half_width+i];
        cL %= GROUP_ORDER;

        NTL::ZZ cR(0); 
        for(int i = 0; i < half_width; ++i)
            cR += a[half_width+i] * b[i];
        cR %= GROUP_ORDER;

        // L
        count = 0;
        for(int i = 0; i < k; ++i)
        {
            int pos = (i<<1) + 1;
            for(int j = pos*half_width, q = 0; j < (pos+1)*half_width; ++j, ++q)
            {
                v = (a[q] * x_values[j]) % GROUP_ORDER;
                convert_ZZ_to_scalar(sc[count], v);
                ptp[count] = &generators[j];
                x_values[j] = (x_values[j] * x) % GROUP_ORDER;
                count++;
            }
        }
        
        int start_pos = 0;
        for(int t = 0; t < MAX_NUM_THREADS_SERVER; ++t)
        {
            res.push_back(pool.enqueue([this, t, start_pos]() 
            {
                ecmult_multi_data_p data; 
                data.sc = &sc[start_pos];
                data.pt = &ptp[start_pos];

                secp256k1_ecmult_multi_var(&ctx->error_callback, scratch[t], &commitment_parts[t], &szero, ecmult_multi_callback_p, &data, (NUM_CHUNKS>>1)/MAX_NUM_THREADS_SERVER);
            }));
            start_pos += (NUM_CHUNKS>>1)/MAX_NUM_THREADS_SERVER;
        }
        
        for(auto &v: res) v.get();
	    res.clear();

        secp256k1_gej_set_infinity(&L);
        for(int t = 0; t < MAX_NUM_THREADS_SERVER; ++t)
            secp256k1_gej_add_var(&L, &L, &commitment_parts[t], NULL);

        convert_ZZ_to_scalar(c, cL);
        secp256k1_ecmult_const(&uc, &u, &c, 256);
        secp256k1_gej_add_var(&L, &L, &uc, NULL);

        secp256k1_ge_set_gej(&temp, &L);
        size_t size = 0;
        secp256k1_eckey_pubkey_serialize(&temp, proof_ptr, &size, 1);

        // Update x with L
        secp256k1_sha256_write(&sha256, proof_ptr, size);
        secp256k1_sha256_finalize(&sha256, random_str);
        
        proof_ptr += size;

        // R
        count = 0;
        for(int i = 0; i < k; ++i)
        {
            int pos = (i<<1);
            for(int j = pos*half_width, q = 0; j < (pos+1)*half_width; ++j, ++q)
            {
                v = (a[half_width+q] * x_values[j]) % GROUP_ORDER;
                convert_ZZ_to_scalar(sc[count], v);
                ptp[count] = &generators[j];
                x_values[j] = (x_values[j] * inv_x) % GROUP_ORDER;
                count++;
            }
        }
        
        start_pos = 0;
        for(int t = 0; t < MAX_NUM_THREADS_SERVER; ++t)
        {
            res.push_back(pool.enqueue([this, t, start_pos]() 
            {
                ecmult_multi_data_p data; 
                data.sc = &sc[start_pos];
                data.pt = &ptp[start_pos];

                secp256k1_ecmult_multi_var(&ctx->error_callback, scratch[t], &commitment_parts[t], &szero, ecmult_multi_callback_p, &data, (NUM_CHUNKS>>1)/MAX_NUM_THREADS_SERVER);
            }));
            start_pos += (NUM_CHUNKS>>1)/MAX_NUM_THREADS_SERVER;
        }
        
        for(auto &v: res) v.get();
	    res.clear();

        secp256k1_gej_set_infinity(&R);
        for(int t = 0; t < MAX_NUM_THREADS_SERVER; ++t)
            secp256k1_gej_add_var(&R, &R, &commitment_parts[t], NULL);
        
        convert_ZZ_to_scalar(c, cR);
        secp256k1_ecmult_const(&uc, &u, &c, 256);
        secp256k1_gej_add_var(&R, &R, &uc, NULL);
        
        secp256k1_ge_set_gej(&temp, &R);
        size = 0;
        secp256k1_eckey_pubkey_serialize(&temp, proof_ptr, &size, 1);

        // Update x with R
        secp256k1_sha256_write(&sha256, proof_ptr, size);
        secp256k1_sha256_finalize(&sha256, random_str);

        proof_ptr += size;

        // Update a'
        for(int i = 0; i < half_width; ++i)
            a[i] = (a[i] * x + a[i+half_width] * inv_x) % GROUP_ORDER;

        // Update b'
        for(int i = 0; i < half_width; ++i)
            b[i] = (b[i] * inv_x + b[i+half_width] * x) % GROUP_ORDER;
    }

    for(int i = 0; i < 2; ++i)
    {
        convert_ZZ_to_arr((uint32_t*)proof_ptr, a[i]);
        proof_ptr += 32;
        convert_ZZ_to_arr((uint32_t*)proof_ptr, b[i]);
        proof_ptr += 32;
    }
} 
#endif

#endif
