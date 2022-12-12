/*
    @author:  Tung Le
    @email:   tungle@vt.edu
    @date:    June 15, 2022
    @warning: this is an academic proof-of-concept prototype and has not received careful code review. 
              this implementation is NOT ready for production use.
*/

#ifndef __CLIENT_H_
#define __CLIENT_H_

#include <iostream>
#include <random>
#include <zmq.hpp>
#include <openssl/aes.h>
#include "Utils/utils.h"
#include "config.hpp"

using namespace     std;

int*                audit_values;
uint8_t             PRF_value[AES_DATA_SIZE];
AES_KEY             MAC_PRF_key;
int*                encryption_level;
int*                encryption_index;
long*               encryption_time;
PRG                 prg;

#ifndef ENABLE_KZG
secp256k1_context   *ctx;
secp256k1_scalar    *sc;
secp256k1_ge        *pt;
secp256k1_ge        **ptp;
secp256k1_scratch   **scratch;
MAC_Block           *commitment_parts;
// Constant 0
secp256k1_scalar    szero;
#else 
bn254_scalar        *sc;
#endif 

// Following are pointers to MAC complements and log structure H for MAC complements
// They are only allocated memory in preprocessing phase
// After computing finished, they are freed so they are not considered to be stored at client side
MAC_Blocks       complements_U;     
MAC_Layer*       complements_H; 

// For measuring amortized cost
double              total_time;

class Client
{
    public:
        // total number of blocks in database
        int              num_blocks;
        // height of hierarchical log structure H
        int              height;     
#ifndef ENABLE_KZG
        // Generators g received from server
        secp256k1_ge*    generators;      
        // alpha*Generators for computing commitments
        secp256k1_ge*    alpha_generators;
        // Generator u for BulletProof 
        secp256k1_ge     u;       
        // Public value h
        secp256k1_ge     h_mac;   
        // Secret key alpha
        secp256k1_scalar alpha;
#endif 
        // the number of write operations so far
        long             write_step;
        // w is omega, the 2n-th primitive root of unity
        NTL::ZZ_p        w;

        // socket connection to server
        zmq::context_t*  context;
        zmq::socket_t*   socket;

        Client();
        ~Client();

        void get_generators();
        void create_data_block(int block_id, Data_Block &data_block);
        void initialize(int num_blocks);
        void compute_commitment(Data_Block &data_block, MAC_Block &commitment);
        void compute_MAC_complement(int level, int index, MAC_Block &MAC_complement);
#ifndef ENABLE_KZG
        void inner_product_verify(MAC_Block &commitment, uint8_t *proof);
#else 
        bool verify_kzg_proof(uint8_t *kzg_proof);
#endif 
        void update(int block_id);
        void audit();
        void self_test();
        
        // // Hierarchical log structure H
        void HRebuildX(int level);
        void HRebuildY(int level);
        void HAdd(MAC_Block &B, int level);
        void mix(MAC_Blocks A0, MAC_Blocks A1, MAC_Blocks A, int length);
        void clear_H(int until_level);
        // CRebuild MAC
        void CRebuild();
};

Client::Client()
{
    context = new zmq::context_t(1);
    socket  = new zmq::socket_t(*context, ZMQ_REQ);
    string server_address = "tcp://localhost:" + to_string(SERVER_PORT);
    cout << "Connecting to " << server_address << endl;
    socket->connect(server_address);
#ifndef ENABLE_KZG
    ctx     = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    sc      = (secp256k1_scalar*)checked_malloc(&ctx->error_callback, sizeof(secp256k1_scalar)*NUM_CHUNKS);
    pt      = (secp256k1_ge*)checked_malloc(&ctx->error_callback, sizeof(secp256k1_ge)*NUM_CHUNKS);
    ptp     = (secp256k1_ge**)checked_malloc(&ctx->error_callback, sizeof(secp256k1_ge*)*NUM_CHUNKS);

    int    bucket_window = secp256k1_pippenger_bucket_window(NUM_CHUNKS/MAX_NUM_THREADS_CLIENT);
    size_t scratch_size  = secp256k1_pippenger_scratch_size(NUM_CHUNKS/MAX_NUM_THREADS_CLIENT, bucket_window);
    scratch = new secp256k1_scratch*[MAX_NUM_THREADS_CLIENT];
    for(int i = 0; i < MAX_NUM_THREADS_CLIENT; ++i)
        scratch[i] = secp256k1_scratch_create(&ctx->error_callback, scratch_size + PIPPENGER_SCRATCH_OBJECTS*ALIGNMENT);
    commitment_parts = new MAC_Block[MAX_NUM_THREADS_CLIENT]; 
    secp256k1_scalar_set_int(&szero, 0);
#else 
    sc      = new bn254_scalar[NUM_CHUNKS];
#endif 
}

Client::~Client()
{

}

void Client::initialize(int num_blocks)
{
    this->num_blocks = num_blocks;
    this->write_step = 0;
    
    // NTL Init
    NTL::ZZ_p::init(PRIME_MODULUS);
    NTL::ZZ_p g = NTL::to_ZZ_p(GENERATOR);
    NTL::ZZ a   = (PRIME_MODULUS-1)/(2 * num_blocks);
    w           = NTL::power(g, a);

    // Public value h for computing MACs of commitments
#ifndef ENABLE_KZG
    // Generate a secket key
    secp256k1_scalar_set_int(&alpha, 0);
    memcpy(alpha.d, SECRET_KEY, 16);

    random_group_element_test(&h_mac);

    // Get generators gi from server
    generators       = new secp256k1_ge[NUM_GENERATORS];
    alpha_generators = new secp256k1_ge[NUM_CHUNKS];
#else 
    GoSlice gs_tau_key;
    gs_tau_key.data   = (void*)TAU_KEY;
    gs_tau_key.len    = gs_tau_key.cap   = 16;

    GoSlice gs_alpha_key;
    gs_alpha_key.data = (void*)SECRET_KEY;
    gs_alpha_key.len  = gs_alpha_key.cap = 16;

    init_key(&gs_tau_key, &gs_alpha_key);
#endif
    get_generators();
    
    // PRF to generate one-time keys
    encryption_level = (int*)&PRF_value[0];
    encryption_index = (int*)&PRF_value[4];
    encryption_time  = (long*)&PRF_value[8];

    // Init AES to use as a PRF function
    AES_set_encrypt_key(SECRET_KEY, AES_KEY_SIZE<<3, &MAC_PRF_key);

    // Other data structures for audit 
    write_step    = 1;
    height        = ceil(log2(num_blocks)) + 1;
    complements_U = new MAC_Block[num_blocks];
    complements_H = new MAC_Layer[height];
    complements_H[height-1].X = new MAC_Block[2<<(height-1)];
    complements_H[height-1].Y = new MAC_Block[2<<(height-1)];
    
    zmq::message_t request_msg(sizeof(num_blocks));
    memcpy((void*)request_msg.data(), &num_blocks, sizeof(num_blocks));
    socket->send(request_msg);

    zmq::message_t reply;
    socket->recv(&reply);
    cout << "[SERVER RESPONSE]: " << reply.to_string() << endl;
    
#ifndef ENABLE_KZG
    secp256k1_scalar data_chunk;
#else 
    bn254_scalar data_chunk;
#endif 
    Data_Block data_block;
    data_block.SetLength(NUM_CHUNKS);

    MAC_Block commitment;

    // Create a database
    int i = 0;
    int remaining = num_blocks;
    while(remaining > 0)
    {
        int num_blocks_sent = (MAX_BLOCKS_SENT < remaining) ? MAX_BLOCKS_SENT : remaining;
        zmq::message_t request(num_blocks_sent*(BLOCK_SIZE+COMMITMENT_MAC_SIZE));
        uint8_t *data_ptr = (uint8_t*)request.data();

        for(int k = 0; k < num_blocks_sent; ++k)
        {
            // Process data parts
            create_data_block(i + 1, data_block);
            for(int j = 0; j < NUM_CHUNKS; ++j)
            {
#ifndef ENABLE_KZG
                convert_ZZ_to_scalar(data_chunk, data_block[j]);
#else 
                convert_ZZ_to_arr(data_chunk, data_block[j]);
#endif 
                memcpy((void*)data_ptr, &data_chunk, sizeof(data_chunk));
                data_ptr += sizeof(data_chunk);
            }
            // Process MAC parts
            compute_commitment(data_block, commitment);
            compute_MAC_complement(0, i + 1, complements_U[i]);
#ifndef ENABLE_KZG
            secp256k1_gej_add_var(&commitment, &commitment, &complements_U[i], NULL);
            memcpy((void*)data_ptr, &commitment, COMMITMENT_MAC_SIZE);
#else 
            bn254_add(commitment, complements_U[i]);
            memcpy((void*)data_ptr, commitment, COMMITMENT_MAC_SIZE);
#endif
            data_ptr += COMMITMENT_MAC_SIZE;

            cout << "Block ID: " << data_block[0] << endl;
            i++;
        }

        // Send data blocks to server
        socket->send(request);

        // Receive response from server
        socket->recv(&reply);
        cout << "[SERVER RESPONSE]: " << reply.to_string() << endl;
        remaining -= num_blocks_sent;
    }

    // Call CRebuild the first time
    CRebuild();

    // Create MAC complements for database C
    MAC_Block updated_MAC_complement;
    MAC_Block temp_gej;
    int l = 1<<(height-1);
    zmq::message_t request((2<<height) * COMMITMENT_MAC_SIZE);
    uint8_t *data_ptr = (uint8_t*)request.data();

#ifndef ENABLE_KZG
    for(int i = 0; i < (l<<1); ++i)
    {
        compute_MAC_complement(height-1, i, updated_MAC_complement);
        if(i >= l)
        {
            secp256k1_gej_neg(&temp_gej, &complements_H[height-1].Y[i-l]);
            secp256k1_gej_add_var(&temp_gej, &temp_gej, &updated_MAC_complement, NULL);
            memcpy((void*)data_ptr, &temp_gej, COMMITMENT_MAC_SIZE);
        }
        else 
        {
            secp256k1_gej_neg(&temp_gej, &complements_H[height-1].X[i]);
            secp256k1_gej_add_var(&temp_gej, &temp_gej, &updated_MAC_complement, NULL);
            memcpy((void*)data_ptr, &temp_gej, COMMITMENT_MAC_SIZE);
        }
        data_ptr += COMMITMENT_MAC_SIZE;
    }
#else 
    for(int i = 0; i < (l<<1); ++i)
    {
        compute_MAC_complement(height-1, i, updated_MAC_complement);
        if(i >= l)
        {
            bn254_neg(complements_H[height-1].Y[i-l]);
            bn254_add(complements_H[height-1].Y[i-l], updated_MAC_complement);
            memcpy((void*)data_ptr, complements_H[height-1].Y[i-l], COMMITMENT_MAC_SIZE);
        }
        else 
        {
            bn254_neg(complements_H[height-1].X[i]);
            bn254_add(complements_H[height-1].X[i], updated_MAC_complement);
            memcpy((void*)data_ptr, complements_H[height-1].X[i], COMMITMENT_MAC_SIZE);
        }
        data_ptr += COMMITMENT_MAC_SIZE;
    }
#endif 

    // Send database to server
    socket->send(request);

    // Receive response from server
    socket->recv(&reply);
    cout << "[SERVER RESPONSE]: " << reply.to_string() << endl;
    
    // Deallocate initial information
    delete [] complements_U;
    delete [] complements_H[height-1].X;
    delete [] complements_H[height-1].Y;
    delete [] complements_H;

    // Allocate a buffer for audit operation
    audit_values = new int[(NUM_CHECK_AUDIT<<1)*height];
    write_step   = 0;
}

void Client::get_generators()
{
#ifndef ENABLE_KZG
    char *request = "GET GENERATORS";
    zmq::message_t request_message(strlen(request));
    memcpy((void*)request_message.data(), request, strlen(request));
    socket->send(request_message);

    zmq::message_t reply;
    socket->recv(&reply);
    uint8_t *data = (uint8_t*)reply.data();
    secp256k1_gej temp;

    for(int i = 0; i < NUM_GENERATORS; ++i)
    {
        memcpy(&generators[i], data, sizeof(secp256k1_ge));
        data += sizeof(secp256k1_ge);
    }
    
    memcpy(&u, data, sizeof(secp256k1_ge));

    for(int i = 0; i < NUM_CHUNKS; ++i)
    {
        secp256k1_ecmult_const(&temp, &generators[i], &alpha, 128);
        secp256k1_ge_set_gej(&alpha_generators[i], &temp);
    }

    cout << "RECEIVED GENERATORS FROM SERVER." << endl;
#else 
    GoInt   SRS_size;
    GoSlice SRS_data;
    uint8_t *data_ptr = new uint8_t[NUM_CHUNKS*32+132];
    SRS_data.data = (void*)data_ptr;
    SRS_data.len = SRS_data.cap = NUM_CHUNKS*32+132;

    init_SRS(NUM_CHUNKS, &SRS_data, &SRS_size);
    cout << "SRS size: " << SRS_size << endl;

    zmq::message_t srs_data_msg(NUM_CHUNKS*32+132);
    memcpy((void*)srs_data_msg.data(), data_ptr, SRS_size);
    socket->send(srs_data_msg);

    zmq::message_t reply;
    socket->recv(&reply);
    cout << "[SERVER RESPONSE]: " << reply.to_string() << endl;
#endif 
}

void Client::create_data_block(int block_id, Data_Block &data_block)
{
    data_block[0] = block_id;   
    for(int j = 1; j < NUM_CHUNKS; ++j)
        data_block[j] = NTL::to_ZZ(NTL::RandomBits_ZZ(256));
}

void Client::compute_commitment(Data_Block &data_block, MAC_Block &commitment)
{
#ifndef ENABLE_KZG
    ThreadPool pool(MAX_NUM_THREADS_CLIENT);
    vector<future<void>> res;
    int start_chunk = 0;
    int end_chunk   = NUM_CHUNKS/MAX_NUM_THREADS_CLIENT;
    
    for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
    {
        res.push_back(pool.enqueue([this, t, start_chunk, end_chunk, &data_block]() 
        {
            int n_points = NUM_CHUNKS/MAX_NUM_THREADS_CLIENT;
            
            ecmult_multi_data data; 
            for(int i = start_chunk; i < end_chunk; ++i)
                convert_ZZ_to_scalar(sc[i], data_block[i]);

            data.sc = &sc[start_chunk];
            data.pt = &alpha_generators[start_chunk];

            secp256k1_ecmult_multi_var(&ctx->error_callback, scratch[t], &commitment_parts[t], &szero, ecmult_multi_callback, &data, n_points);
        }));
        start_chunk = end_chunk;
        end_chunk  += NUM_CHUNKS/MAX_NUM_THREADS_CLIENT;
    }

    for(auto &v: res) v.get();
	res.clear();
    
    secp256k1_gej_set_infinity(&commitment);
    for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
        secp256k1_gej_add_var(&commitment, &commitment, &commitment_parts[t], NULL);
#else 
    for(int i = 0; i < NUM_CHUNKS; ++i)
        convert_ZZ_to_scalar(sc[i], data_block[i]);

    GoSlice gs_data_in;
    gs_data_in.data = (void*)sc;
    gs_data_in.len  = gs_data_in.cap = BLOCK_SIZE;
    
    GoSlice gs_commitment;
    gs_commitment.data = (void*)commitment;
    gs_commitment.len  = gs_commitment.cap = 64;

    compute_digest(&gs_data_in, &gs_commitment);
#endif 
}

void Client::compute_MAC_complement(int level, int index, MAC_Block &MAC_complement)
{
#ifndef ENABLE_KZG
    *encryption_level = level;
    *encryption_index = index;
    *encryption_time  = write_step;
    AES_encrypt(PRF_value, PRF_value, &MAC_PRF_key);

    secp256k1_scalar r;
    secp256k1_scalar_set_int(&r, 0);
    secp256k1_gej_set_infinity(&MAC_complement);

    r.d[0] = *(uint64_t*)&PRF_value[0];
    r.d[1] = *(uint64_t*)&PRF_value[8];
    secp256k1_ecmult_const(&MAC_complement, &h_mac, &r, 128);
#else 
    *encryption_level = level;
    *encryption_index = index;
    *encryption_time  = write_step;

    AES_encrypt(PRF_value, PRF_value, &MAC_PRF_key);
    
    GoSlice gs_data_in;
    gs_data_in.data = (void*)PRF_value;
    gs_data_in.len  = gs_data_in.cap = 16;
    
    GoSlice gs_complement;
    gs_complement.data = (void*)MAC_complement;
    gs_complement.len  = gs_complement.cap = 64;

    compute_digest_complement(&gs_data_in, &gs_complement);
#endif 
}

void Client::update(int block_id)
{
    // Preprocessing phase in update
    // Generate a data block with given block id and random data
    Data_Block data_block;
    data_block.SetLength(NUM_CHUNKS);
    create_data_block(block_id, data_block);

    // Compute MAC complement with current time step
    MAC_Block MAC_complement;
    compute_MAC_complement(0, block_id, MAC_complement);

    // Compute updated MAC of commitment
    MAC_Block MAC_commitment;
    compute_commitment(data_block, MAC_commitment);

    // Add commitment and MAC complement that will be sent to server
#ifndef ENABLE_KZG
    secp256k1_gej_add_var(&MAC_commitment, &MAC_commitment, &MAC_complement, NULL); 
#else 
    bn254_add(MAC_commitment, MAC_complement);
#endif 
    // Update write time
    write_step++;
    int updated_level = height-1;

    if(write_step % num_blocks == 0)
    {
        // Rebuild C
        cout << "WRITE STEP #" << write_step << " - C IS REBUILT" << endl;

        write_step               -= num_blocks;
        complements_U             = new MAC_Block[num_blocks];
        complements_H             = new MAC_Layer[height];
        complements_H[height-1].X = new MAC_Block[1<<(height-1)];
        complements_H[height-1].Y = new MAC_Block[1<<(height-1)];

        for(int i = 0; i < num_blocks; ++i) {
            compute_MAC_complement(0, i+1, complements_U[i]);
            write_step++;
        }

        CRebuild();
        
        delete [] complements_U;
    }
    else 
    {
        long saved_write_step = write_step;

        // Update H
        updated_level = 0;
        while(((write_step>>updated_level) & 0x1) == 0)
            updated_level++;

        long time_step_value = write_step & ~(1 << updated_level);   
        int l = 2;
        
        complements_H = new MAC_Layer[updated_level+1];

        for(int i = 0; i < updated_level + 1; ++i)
        {
            complements_H[i].X = new MAC_Block[l];
            complements_H[i].Y = new MAC_Block[l];
            complements_H[i].empty = true;
            l <<= 1;
        }
        
        for(int i = updated_level - 1; i >= 0; --i)
        {
            time_step_value |= (1 << i);
            write_step = time_step_value;
            for(int j = 0; j < (1<<i); ++j)
            {
                compute_MAC_complement(i, j, complements_H[i].X[j]);
                compute_MAC_complement(i, j + (1<<i), complements_H[i].Y[j]);
            }
        }

        write_step = saved_write_step;
        HAdd(MAC_complement, updated_level); 
        cout << "WRITE STEP #" << write_step << " - H-" << updated_level << " IS UPDATED" << endl;

        for(int i = 0; i < updated_level; ++i) 
        {
            delete [] complements_H[i].X;
            delete [] complements_H[i].Y;
        }
    }

    // Main phase
    auto start = clock_start();
    
    // Create update request 
    zmq::message_t request(1 + BLOCK_SIZE + ((2<<updated_level)+1)*COMMITMENT_MAC_SIZE);
    *(char*)request.data() = 'U';
#ifndef ENABLE_KZG
    secp256k1_scalar data_chunk;
#else 
    bn254_scalar     data_chunk;
#endif 
    uint8_t *data_ptr = (uint8_t*)request.data() + 1;

    for(int i = 0; i < NUM_CHUNKS; ++i)
    {
#ifndef ENABLE_KZG
        convert_ZZ_to_scalar(data_chunk, data_block[i]);
        memcpy((void*)data_ptr, &data_chunk, sizeof(secp256k1_scalar));
        data_ptr += sizeof(secp256k1_scalar);
#else 
        convert_ZZ_to_arr(data_chunk, data_block[i]);
        memcpy((void*)data_ptr, data_chunk, sizeof(bn254_scalar));
        data_ptr += sizeof(bn254_scalar);
#endif 
    }

    memcpy((void*)(request.data()+1+BLOCK_SIZE), &MAC_commitment, COMMITMENT_MAC_SIZE);

#ifndef ENABLE_KZG 
    secp256k1_ge  temp_ge;
    secp256k1_gej temp_gej;
    secp256k1_gej updated_MAC_complement;
#else 
    MAC_Block updated_MAC_complement;
#endif 
    data_ptr = (uint8_t*)request.data() + 1 + BLOCK_SIZE + COMMITMENT_MAC_SIZE;

    // Compute new MAC hiding parts
    int l = (1<<updated_level);
    for(int i = 0; i < (l<<1); ++i)
    {   
        compute_MAC_complement(updated_level, i, updated_MAC_complement);
        if(i >= l)
        {
#ifndef ENABLE_KZG
            secp256k1_gej_neg(&temp_gej, &complements_H[updated_level].Y[i-l]);
            secp256k1_gej_add_var(&temp_gej, &temp_gej, &updated_MAC_complement, NULL);
            memcpy((void*)data_ptr, &temp_gej, COMMITMENT_MAC_SIZE);
#else 
            bn254_neg(complements_H[updated_level].Y[i-l]);
            bn254_add(complements_H[updated_level].Y[i-l], updated_MAC_complement);
            memcpy((void*)data_ptr, complements_H[updated_level].Y[i-l], COMMITMENT_MAC_SIZE);
#endif 
        }
        else 
        {
#ifndef ENABLE_KZG
            secp256k1_gej_neg(&temp_gej, &complements_H[updated_level].X[i]);
            secp256k1_gej_add_var(&temp_gej, &temp_gej, &updated_MAC_complement, NULL);
            memcpy((void*)data_ptr, &temp_gej, COMMITMENT_MAC_SIZE);
#else 
            bn254_neg(complements_H[updated_level].X[i]);
            bn254_add(complements_H[updated_level].X[i], updated_MAC_complement);
            memcpy((void*)data_ptr, complements_H[updated_level].X[i], COMMITMENT_MAC_SIZE);
#endif 
        }     
        data_ptr += COMMITMENT_MAC_SIZE;
    } 
    
    // Send request
    socket->send(request);
    
    // Wait for reply
    zmq::message_t reply;
    socket->recv(&reply);

    // Accumulate time cost of each request
    total_time += time_from(start);

    cout << "[SERVER RESPONSE]: " << reply.to_string() << endl;

    delete [] complements_H[updated_level].X;
    delete [] complements_H[updated_level].Y;
    delete [] complements_H;
}

void Client::audit()
{
    // Preprocessing phase
    complements_H = new MAC_Layer[height];

    long saved_write_step = write_step;
    for(int i = 0; i < height; ++i)
    {
        if(((write_step % num_blocks)>>i) & 0x1 || (i == height-1))
        {
            complements_H[i].X = new MAC_Block[1<<i];
            complements_H[i].Y = new MAC_Block[1<<i];

            write_step &= ~((1<<i)-1);
            for(int j = 0; j < (1<<i); ++j)
            {
                compute_MAC_complement(i, j, complements_H[i].X[j]);
                compute_MAC_complement(i, j + (1<<i), complements_H[i].Y[j]);
            }
        }
        write_step = saved_write_step;
    }

    // Main phase
    auto start = clock_start();

    int l        = 1;
    int n_points = 0;

#ifndef ENABLE_KZG
    secp256k1_gej     combined_MAC_complements;
    secp256k1_scalar  *sc = new secp256k1_scalar[NUM_CHECK_AUDIT*height];
    secp256k1_ge      *pt = new secp256k1_ge[NUM_CHECK_AUDIT*height];
#else 
    MAC_Block     combined_MAC_complements;
    bn254_scalar  *sc  = new bn254_scalar[NUM_CHECK_AUDIT*height];
    MAC_Block     *pt  = new MAC_Block[NUM_CHECK_AUDIT*height];
#endif 

    block seed;
    prg.random_block(&seed);

    // Send audit request to server
    zmq::message_t request(1+sizeof(block));
    *(char*)request.data() = 'A';
    memcpy((void*)(request.data()+1), &seed, sizeof(block));
    socket->send(request);

    // Generate random values from the random seed
    prg.reseed(&seed, 0);
    prg.random_data((void*)audit_values, sizeof(int)*(NUM_CHECK_AUDIT<<1)*height);

    int *audit_values_ptr = audit_values;
    
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
                    if(index >= l)
                        secp256k1_ge_set_gej(&pt[n_points], &complements_H[i].Y[index-l]);
                    else 
                        secp256k1_ge_set_gej(&pt[n_points], &complements_H[i].X[index]);
#else 
                    bn254_scalar_set_int(sc[n_points], coeff);
                    if(index >= l)
                        memcpy(pt[n_points], complements_H[i].Y[index-l], COMMITMENT_MAC_SIZE);
                    else 
                        memcpy(pt[n_points], complements_H[i].X[index], COMMITMENT_MAC_SIZE);
#endif
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

                    if(j >= l)
                        secp256k1_ge_set_gej(&pt[n_points], &complements_H[i].Y[j-l]);
                    else 
                        secp256k1_ge_set_gej(&pt[n_points], &complements_H[i].X[j]);    
#else 
                    bn254_scalar_set_int(sc[n_points], coeff);
                    if(j >= l)
                        memcpy(pt[n_points], complements_H[i].Y[j-l], COMMITMENT_MAC_SIZE);
                    else 
                        memcpy(pt[n_points], complements_H[i].X[j], COMMITMENT_MAC_SIZE);
#endif 
                    n_points++;
                }
            }
        }
        l <<= 1;
    }

#ifndef ENABLE_KZG
    int n_point_each_thread = n_points/MAX_NUM_THREADS_CLIENT;
    secp256k1_scratch **scratch = new secp256k1_scratch*[MAX_NUM_THREADS_CLIENT];
    int bucket_window;
    size_t scratch_size;

    for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
    {
        if(t == MAX_NUM_THREADS_CLIENT - 1)
            n_point_each_thread = n_points - n_point_each_thread*t;
        bucket_window = secp256k1_pippenger_bucket_window(n_point_each_thread);
        scratch_size  = secp256k1_pippenger_scratch_size(n_point_each_thread, bucket_window);
        scratch[t] = secp256k1_scratch_create(&ctx->error_callback, scratch_size + PIPPENGER_SCRATCH_OBJECTS*ALIGNMENT);
    }

    ThreadPool pool(MAX_NUM_THREADS_CLIENT);
    vector<future<void>> res;
    MAC_Block *complements = new MAC_Block[MAX_NUM_THREADS_CLIENT];

    n_point_each_thread = n_points/MAX_NUM_THREADS_CLIENT;

    int start_pos = 0;
    for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
    {
        if(t == MAX_NUM_THREADS_CLIENT-1) 
            n_point_each_thread = n_points - n_point_each_thread*t;
        res.push_back(pool.enqueue([this, start_pos, t, pt, sc, scratch, complements, n_point_each_thread]() 
        {
            ecmult_multi_data data; 
            data.sc = &sc[start_pos];
            data.pt = &pt[start_pos];

            secp256k1_ecmult_multi_var(&ctx->error_callback, scratch[t], &complements[t], &szero, ecmult_multi_callback, &data, n_point_each_thread);
        }));
        start_pos += n_point_each_thread;
    }
    for(auto &v: res) v.get();
	res.clear();

    secp256k1_gej_set_infinity(&combined_MAC_complements);
    for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
        secp256k1_gej_add_var(&combined_MAC_complements, &combined_MAC_complements, &complements[t], NULL);
    
    for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
        delete [] scratch[t];
    delete [] scratch;
    delete [] complements;

#else 
    bn254_multi_exp(combined_MAC_complements, pt, sc, n_points);
#endif 
    // Wait for reply
    zmq::message_t reply;
    socket->recv(&reply);

#ifndef ENABLE_KZG
    // Check results
    secp256k1_ge  temp;

    // Compute MAC based on commitment received from server
    secp256k1_gej commitment;
    secp256k1_gej commitment_cp;

    secp256k1_eckey_pubkey_parse(&temp, (uint8_t*)reply.data(), 33);
    secp256k1_gej_set_ge(&commitment_cp, &temp);

    secp256k1_ecmult_const(&commitment, &temp, &alpha, 128);
    secp256k1_gej_add_var(&commitment, &commitment, &combined_MAC_complements, NULL);
    
    // Compute MAC stored at server
    secp256k1_gej combined_MAC;
    secp256k1_eckey_pubkey_parse(&temp, (uint8_t*)reply.data()+33, 33);
    secp256k1_gej_set_ge(&combined_MAC, &temp);

    secp256k1_gej combined_align;
    secp256k1_eckey_pubkey_parse(&temp, (uint8_t*)reply.data()+66, 33);
    secp256k1_ecmult_const(&combined_align, &temp, &alpha, 128);
    
    secp256k1_gej_add_var(&combined_MAC, &combined_MAC, &combined_align, NULL);

    secp256k1_ge r1, r2;
    secp256k1_ge_set_gej(&r1, &commitment);
    secp256k1_ge_set_gej(&r2, &combined_MAC);
    ge_equals_ge(&r1, &r2);

    cout << "DATA IS FULL." << endl;
    
    uint8_t *proof = (uint8_t*)reply.data() + 99;

    auto start_verify = clock_start();

    res.push_back(pool.enqueue([this, &commitment_cp, proof]() 
    {
        NTL::ZZ_p::init(GROUP_ORDER);
        inner_product_verify(commitment_cp, proof);
    }));
    for(auto &v: res) v.get();
	res.clear();

    cout << "Verification time: " << time_from(start_verify) << endl;
#else 
    // Compute MAC based on commitment received from server
    MAC_Block commitment;
    memcpy(commitment, reply.data(), COMMITMENT_MAC_SIZE);

    bn254_scalar alpha;
    memset(alpha, 0, sizeof(bn254_scalar));
    memcpy((uint8_t*)alpha+16, SECRET_KEY, 16); 

    bn254_mult(commitment, alpha);
    bn254_add(commitment, combined_MAC_complements);

    // Compute MAC stored at server
    MAC_Block combined_MAC;
    memcpy(combined_MAC, reply.data()+192, COMMITMENT_MAC_SIZE);
    
    MAC_Block combined_align;
    memcpy(combined_align, reply.data()+192+COMMITMENT_MAC_SIZE, COMMITMENT_MAC_SIZE);

    bn254_mult(combined_align, alpha);
    bn254_add(combined_MAC, combined_align);
    
    bool is_honest = verify_kzg_proof((uint8_t*)reply.data()); 
    bool is_full   = bn254_compare(commitment, combined_MAC);
    if(is_honest && is_full)
        cout << "DATA IS FULL." << endl;
    else 
    {
        cout << "DATA HAS BEEN LOST!" << endl;
        exit(1);
    }
#endif    
    cout << "Audit time: " << time_from(start) << endl; 
    
    // Deallocate memory used for computing MAC complements
    for(int i = 0; i < height; ++i)
    {
        if(((write_step % num_blocks)>>i) & 0x1 || (i == height-1))
        {
            delete [] complements_H[i].X;
            delete [] complements_H[i].Y;
        }
    }
    delete [] complements_H;
    delete [] sc;
    delete [] pt;
}

void Client::self_test()
{   
    // This total_time is used to compute average time cost
    total_time = 0;
    int k = 0;
    for(; k < 10; ++k)
    {
        cout << "Round #" << k << endl;
        // audit();
        for(int i = 0; i < num_blocks; ++i)
        {
            cout << "Iteration i: " << i << endl;
            update(i+1);
            // audit();
            if(i == num_blocks-1) 
            {
                for(int j = 0; j < 100; ++j)
                    audit();
            }
            // check_MAC_complements();
        }
    } 
    
    cout << "Total number of requests: " << (k * (num_blocks - 1)) << endl;
    cout << "Amortized cost for each request: " << (total_time/(k * (num_blocks - 1))) << endl;
}

void Client::mix(MAC_Blocks A0, MAC_Blocks A1, MAC_Blocks A, int length)
{   
    ThreadPool pool(MAX_NUM_THREADS_CLIENT);
    vector<future<void>> res;
    
    int n_threads = (length > MAX_NUM_THREADS_CLIENT) ? MAX_NUM_THREADS_CLIENT : length;
    int start_pos = 0;
    int end_pos   = length/n_threads;

    for(int t = 0; t < n_threads; ++t)
    {
        res.push_back(pool.enqueue([this, start_pos, end_pos, A, A0, A1, length]() 
        {
            NTL::ZZ_p::init(PRIME_MODULUS);
            NTL::ZZ_p v  = NTL::power(w, num_blocks/length);
            NTL::ZZ_p vi = power(v, start_pos);
            NTL::ZZ   vi_ZZ;
            conv(vi_ZZ, vi);
#ifndef ENABLE_KZG
            secp256k1_scalar vi_MAC;
            secp256k1_gej    value;
#else 
            bn254_scalar vi_MAC;
            MAC_Block    value;
#endif 
            for (int i = start_pos; i < end_pos; ++i)
            {
                convert_ZZ_to_scalar(vi_MAC, vi_ZZ);
#ifndef ENABLE_KZG
                secp256k1_ecmult(&value, &A1[i], &vi_MAC, NULL);
                secp256k1_gej_add_var(&A[i], &A0[i], &value, NULL); 

                secp256k1_gej_neg(&value, &value);
                secp256k1_gej_add_var(&A[i+length], &A0[i], &value, NULL);
#else 
                memcpy(value, A1[i], COMMITMENT_MAC_SIZE);
                bn254_mult(value, vi_MAC);

                memcpy(A[i], A0[i], COMMITMENT_MAC_SIZE);
                bn254_add(A[i], value); 

                bn254_neg(value);
                memcpy(A[i+length], A0[i], COMMITMENT_MAC_SIZE);
                bn254_add(A[i+length], value);
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

void Client::HRebuildX(int level)
{
    for (int i = 0; i < level; i++)
        mix(complements_H[i].X, &complements_H[i].X[1<<i], &complements_H[i+1].X[2<<i], 1<<i);
    
    for(int i = 0; i < (1<<level); ++i)
        memcpy(&complements_H[level].X[i], &complements_H[level].X[(1<<level)+i], COMMITMENT_MAC_SIZE);
}

void Client::HRebuildY(int level)
{
    for (int i = 0; i < level; i++)
        mix(complements_H[i].Y, &complements_H[i].Y[1<<i], &complements_H[i+1].Y[2<<i], 1<<i);
    
    for(int i = 0; i < (1<<level); ++i)
        memcpy(&complements_H[level].Y[i], &complements_H[level].Y[(1<<level)+i], COMMITMENT_MAC_SIZE);
}

void Client::HAdd(MAC_Block &B, int level)
{
    NTL::ZZ_p wt = NTL::power(w, reverse_bits(write_step % num_blocks, height-1));
    NTL::ZZ   wt_ZZ;
    conv(wt_ZZ, wt);
#ifndef ENABLE_KZG
    secp256k1_scalar wt_secp256k1;
    convert_ZZ_to_scalar(wt_secp256k1, wt_ZZ);

    MAC_Block B2;
    secp256k1_ge B_prime;    
    secp256k1_ecmult(&B2, &B, &wt_secp256k1, NULL);
#else 
    bn254_scalar wt_bn254;
    convert_ZZ_to_scalar(wt_bn254, wt_ZZ);

    MAC_Block B2;
    memcpy(B2, B, COMMITMENT_MAC_SIZE);
    bn254_mult(B2, wt_bn254);
#endif 
    if (level == 0)
    {
#ifndef ENABLE_KZG
        complements_H[0].X[0]  = B;
        complements_H[0].Y[0]  = B2;
#else 
        memcpy(complements_H[0].X[0], B,  COMMITMENT_MAC_SIZE);
        memcpy(complements_H[0].Y[0], B2, COMMITMENT_MAC_SIZE);
#endif 
    }
    else
    {
#ifndef ENABLE_KZG
        complements_H[0].X[1]  = B;
        complements_H[0].Y[1]  = B2;
#else 
        memcpy(complements_H[0].X[1], B,  COMMITMENT_MAC_SIZE);
        memcpy(complements_H[0].Y[1], B2, COMMITMENT_MAC_SIZE);
#endif 
        HRebuildX(level);
        HRebuildY(level);
    }
}

void Client::CRebuild()
{
    // Add blocks from U to rebuild C (H at level k+1)         
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

    ThreadPool pool(MAX_NUM_THREADS_CLIENT);
    vector<future<void>> res;

    int start_pos = 0;
    int end_pos   = num_blocks/MAX_NUM_THREADS_CLIENT;

    // Copy data from raw buffer U
    for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
    {
        res.push_back(pool.enqueue([this, start_pos, end_pos, &wt_ZZ, &wt_MAC]() 
        {
            for(int i = start_pos; i < end_pos; ++i)
            {
#ifndef ENABLE_KZG
                memcpy(&complements_H[height-1].X[i], &complements_U[i], COMMITMENT_MAC_SIZE);
                secp256k1_ecmult(&complements_H[height-1].Y[i], &complements_U[i], &wt_MAC, NULL);
#else 
                memcpy(complements_H[height-1].X[i], complements_U[i], COMMITMENT_MAC_SIZE);
                memcpy(complements_H[height-1].Y[i], complements_U[i], COMMITMENT_MAC_SIZE);
                bn254_mult(complements_H[height-1].Y[i], wt_MAC);
#endif
            }
        }));
        start_pos = end_pos;
        end_pos  += num_blocks/MAX_NUM_THREADS_CLIENT;
    }
    for(auto &v: res) v.get(); res.clear();

    // Perform according to encode algorithm
#ifndef ENABLE_KZG
    secp256k1_scalar vi_MAC;
    
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

        ThreadPool pool(MAX_NUM_THREADS_CLIENT);
        vector<future<void>> res;

        if(m2 < MAX_NUM_THREADS_CLIENT)
        {
            for(int j = 0; j < m2; ++j)
            {
                convert_ZZ_to_scalar(vi_MAC, vi_ZZ);
                int range_per_thread = m * ceil((num_blocks-j+1)/m/MAX_NUM_THREADS_CLIENT);
                int start_pos = j;
                int end_pos   = j + range_per_thread;
                for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
                {
                    res.push_back(pool.enqueue([this, start_pos, end_pos, m, m2, &vi_ZZ, &vi_MAC]() 
                    {
                        secp256k1_gej u_gej, t_gej;
                        for(int k = start_pos; k < end_pos; k += m)
                        {
                            secp256k1_ecmult(&t_gej, &complements_H[height-1].X[k+m2], &vi_MAC, NULL);
                            memcpy(&u_gej, &complements_H[height-1].X[k], COMMITMENT_MAC_SIZE);

                            secp256k1_gej_add_var(&complements_H[height-1].X[k], &u_gej, &t_gej, NULL); 

                            secp256k1_gej_neg(&t_gej, &t_gej);
                            secp256k1_gej_add_var(&complements_H[height-1].X[k+m2], &u_gej, &t_gej, NULL);
                        }
                    }));
                    start_pos = end_pos;
                    if(t == MAX_NUM_THREADS_CLIENT-2)
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
            int end_pos   = m2/MAX_NUM_THREADS_CLIENT;
            for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
            {
                res.push_back(pool.enqueue([this, start_pos, end_pos, m, m2, &v]() 
                {
                    NTL::ZZ_p::init(PRIME_MODULUS);
                    secp256k1_gej    u_gej, t_gej;
                    NTL::ZZ_p        vi = NTL::power(v, start_pos);
                    NTL::ZZ          vi_ZZ;
                    secp256k1_scalar vi_MAC;

                    conv(vi_ZZ, vi);
                    for(int j = start_pos; j < end_pos; ++j)
                    {
                        convert_ZZ_to_scalar(vi_MAC, vi_ZZ);
                        for(int k = j; k < num_blocks; k += m)
                        {
                            secp256k1_ecmult(&t_gej, &complements_H[height-1].X[k+m2], &vi_MAC, NULL);
                            memcpy(&u_gej, &complements_H[height-1].X[k], COMMITMENT_MAC_SIZE);

                            secp256k1_gej_add_var(&complements_H[height-1].X[k], &u_gej, &t_gej, NULL); 

                            secp256k1_gej_neg(&t_gej, &t_gej);
                            secp256k1_gej_add_var(&complements_H[height-1].X[k+m2], &u_gej, &t_gej, NULL);
                        }
                        vi *= v;
                        conv(vi_ZZ, vi);
                    }
                }));
                start_pos = end_pos;
                end_pos  += m2/MAX_NUM_THREADS_CLIENT;
            }
            for(auto &v: res) v.get(); res.clear();
        }
    }

    secp256k1_gej u_gej, t_gej;
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

        ThreadPool pool(MAX_NUM_THREADS_CLIENT);
        vector<future<void>> res;

        if(m2 < MAX_NUM_THREADS_CLIENT)
        {
            for(int j = 0; j < m2; ++j)
            {
                convert_ZZ_to_scalar(vi_MAC, vi_ZZ);
                int range_per_thread = m * ceil((num_blocks-j+1)/m/MAX_NUM_THREADS_CLIENT);
                int start_pos = j;
                int end_pos   = j + range_per_thread;
                for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
                {
                    res.push_back(pool.enqueue([this, start_pos, end_pos, m, m2, &vi_ZZ, &vi_MAC]() 
                    {
                        secp256k1_gej u_gej, t_gej;
                        for(int k = start_pos; k < end_pos; k += m)
                        {
                            secp256k1_ecmult(&t_gej, &complements_H[height-1].Y[k+m2], &vi_MAC, NULL);
                            memcpy(&u_gej, &complements_H[height-1].Y[k], COMMITMENT_MAC_SIZE);

                            secp256k1_gej_add_var(&complements_H[height-1].Y[k], &u_gej, &t_gej, NULL); 

                            secp256k1_gej_neg(&t_gej, &t_gej);
                            secp256k1_gej_add_var(&complements_H[height-1].Y[k+m2], &u_gej, &t_gej, NULL);
                        }
                    }));
                    start_pos = end_pos;
                    if(t == MAX_NUM_THREADS_CLIENT-2)
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
            int end_pos   = m2/MAX_NUM_THREADS_CLIENT;
            for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
            {
                res.push_back(pool.enqueue([this, start_pos, end_pos, m, m2, &v]() 
                {
                    NTL::ZZ_p::init(PRIME_MODULUS);
                    secp256k1_gej    u_gej, t_gej;
                    NTL::ZZ_p        vi = NTL::power(v, start_pos);
                    NTL::ZZ          vi_ZZ;
                    secp256k1_scalar vi_MAC;

                    conv(vi_ZZ, vi);
                    for(int j = start_pos; j < end_pos; ++j)
                    {
                        convert_ZZ_to_scalar(vi_MAC, vi_ZZ);
                        for(int k = j; k < num_blocks; k += m)
                        {
                            secp256k1_ecmult(&t_gej, &complements_H[height-1].Y[k+m2], &vi_MAC, NULL);
                            memcpy(&u_gej, &complements_H[height-1].Y[k], COMMITMENT_MAC_SIZE);

                            secp256k1_gej_add_var(&complements_H[height-1].Y[k], &u_gej, &t_gej, NULL); 

                            secp256k1_gej_neg(&t_gej, &t_gej);
                            secp256k1_gej_add_var(&complements_H[height-1].Y[k+m2], &u_gej, &t_gej, NULL);
                        }
                        vi *= v;
                        conv(vi_ZZ, vi);
                    }
                }));
                start_pos = end_pos;
                end_pos  += m2/MAX_NUM_THREADS_CLIENT;
            }
            for(auto &v: res) v.get(); res.clear();
        }
    }
#else 
    bn254_scalar vi_MAC;

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

        ThreadPool pool(MAX_NUM_THREADS_CLIENT);
        vector<future<void>> res;

        if(m2 < MAX_NUM_THREADS_CLIENT)
        {
            for(int j = 0; j < m2; ++j)
            {
                convert_ZZ_to_scalar(vi_MAC, vi_ZZ);
                int range_per_thread = m * ceil((num_blocks-j+1)/m/MAX_NUM_THREADS_CLIENT);
                int start_pos = j;
                int end_pos   = j + range_per_thread;

                for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
                {
                    res.push_back(pool.enqueue([this, start_pos, end_pos, m, m2, &vi_ZZ, &vi_MAC]() 
                    {
                        MAC_Block u, t;
                        for(int k = start_pos; k < end_pos; k += m)
                        {
                            memcpy(t, complements_H[height-1].X[k+m2], COMMITMENT_MAC_SIZE);
                            bn254_mult(t, vi_MAC);
                            memcpy(u, complements_H[height-1].X[k], COMMITMENT_MAC_SIZE);

                            bn254_add(complements_H[height-1].X[k], t); 

                            bn254_neg(t);
                            memcpy(complements_H[height-1].X[k+m2], u, COMMITMENT_MAC_SIZE);
                            bn254_add(complements_H[height-1].X[k+m2], t);
                        }
                    }));
                    start_pos = end_pos;
                    if(t == MAX_NUM_THREADS_CLIENT-2)
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
            int end_pos   = m2/MAX_NUM_THREADS_CLIENT;
            for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
            {
                res.push_back(pool.enqueue([this, start_pos, end_pos, m, m2, &v]() 
                {
                    NTL::ZZ_p::init(PRIME_MODULUS);
                    MAC_Block        u, t;
                    NTL::ZZ_p        vi = NTL::power(v, start_pos);
                    NTL::ZZ          vi_ZZ;
                    bn254_scalar     vi_MAC;

                    conv(vi_ZZ, vi);
                    for(int j = start_pos; j < end_pos; ++j)
                    {
                        convert_ZZ_to_scalar(vi_MAC, vi_ZZ);
                        for(int k = j; k < num_blocks; k += m)
                        {
                            memcpy(t, complements_H[height-1].X[k+m2], COMMITMENT_MAC_SIZE);
                            bn254_mult(t, vi_MAC);
                            memcpy(u, complements_H[height-1].X[k], COMMITMENT_MAC_SIZE);

                            bn254_add(complements_H[height-1].X[k], t); 

                            bn254_neg(t);
                            memcpy(complements_H[height-1].X[k+m2], u, COMMITMENT_MAC_SIZE);
                            bn254_add(complements_H[height-1].X[k+m2], t);
                        }
                        vi *= v;
                        conv(vi_ZZ, vi);
                    }
                }));
                start_pos = end_pos;
                end_pos  += m2/MAX_NUM_THREADS_CLIENT;
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

        ThreadPool pool(MAX_NUM_THREADS_CLIENT);
        vector<future<void>> res;

        if(m2 < MAX_NUM_THREADS_CLIENT)
        {
            for(int j = 0; j < m2; ++j)
            {
                convert_ZZ_to_scalar(vi_MAC, vi_ZZ);
                int range_per_thread = m * ceil((num_blocks-j+1)/m/MAX_NUM_THREADS_CLIENT);
                int start_pos = j;
                int end_pos   = j + range_per_thread;
                
                for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
                {
                    res.push_back(pool.enqueue([this, start_pos, end_pos, m, m2, &vi_ZZ, &vi_MAC]() 
                    {
                        MAC_Block u, t;
                        for(int k = start_pos; k < end_pos; k += m)
                        {
                            memcpy(t, complements_H[height-1].Y[k+m2], COMMITMENT_MAC_SIZE);
                            bn254_mult(t, vi_MAC);
                            memcpy(u, complements_H[height-1].Y[k], COMMITMENT_MAC_SIZE);

                            bn254_add(complements_H[height-1].Y[k], t); 

                            bn254_neg(t);
                            memcpy(complements_H[height-1].Y[k+m2], u, COMMITMENT_MAC_SIZE);
                            bn254_add(complements_H[height-1].Y[k+m2], t);
                        }
                    }));
                    start_pos = end_pos;
                    if(t == MAX_NUM_THREADS_CLIENT-2)
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
            int end_pos   = m2/MAX_NUM_THREADS_CLIENT;
            for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
            {
                res.push_back(pool.enqueue([this, start_pos, end_pos, m, m2, &v]() 
                {
                    NTL::ZZ_p::init(PRIME_MODULUS);
                    MAC_Block        u, t;
                    NTL::ZZ_p        vi = NTL::power(v, start_pos);
                    NTL::ZZ          vi_ZZ;
                    bn254_scalar     vi_MAC;

                    conv(vi_ZZ, vi);
                    for(int j = start_pos; j < end_pos; ++j)
                    {
                        convert_ZZ_to_scalar(vi_MAC, vi_ZZ);
                        for(int k = j; k < num_blocks; k += m)
                        {
                            memcpy(t, complements_H[height-1].Y[k+m2], COMMITMENT_MAC_SIZE);
                            bn254_mult(t, vi_MAC);
                            memcpy(u, complements_H[height-1].Y[k], COMMITMENT_MAC_SIZE);

                            bn254_add(complements_H[height-1].Y[k], t); 

                            bn254_neg(t);
                            memcpy(complements_H[height-1].Y[k+m2], u, COMMITMENT_MAC_SIZE);
                            bn254_add(complements_H[height-1].Y[k+m2], t);
                        }
                        vi *= v;
                        conv(vi_ZZ, vi);
                    }
                }));
                start_pos = end_pos;
                end_pos  += m2/MAX_NUM_THREADS_CLIENT;
            }
            for(auto &v: res) v.get(); res.clear();
        }
    }
#endif 
    cout << endl;
}

void Client::clear_H(int until_level)
{
    for (int i = 0; i < until_level; ++i) 
    {
        delete [] complements_H[i].X;
        delete [] complements_H[i].Y;
    }
}

#ifndef ENABLE_KZG
void Client::inner_product_verify(MAC_Block &commitment, uint8_t *proof)
{
    uint8_t *proof_ptr = proof;
    
    unsigned char random_str[] = "hash of P, c, etc. all that jazz";

    secp256k1_scalar  c, sc_x, sc_inv_x;
    secp256k1_gej     uc;
    secp256k1_gej     L;
    secp256k1_gej     R;
    secp256k1_ge      temp;

    NTL::ZZ c_ZZ;

    convert_arr_to_scalar(c, (uint32_t*)proof);

    secp256k1_ecmult_const(&uc, &u, &c, 256);
    secp256k1_gej_add_var(&commitment, &commitment, &uc, NULL);

    proof_ptr += 32;

    size_t   half_width, k;

    NTL::vec_ZZ x_values;
    x_values.SetLength(NUM_CHUNKS);
    for(int i = 0; i < NUM_CHUNKS; ++i)
        x_values[i] = 1;
    
    secp256k1_sha256 sha256;
    secp256k1_sha256_initialize(&sha256);
    secp256k1_sha256_write(&sha256, random_str, 32);
    secp256k1_sha256_write(&sha256, proof, 32);
    secp256k1_sha256_finalize(&sha256, random_str);

    NTL::ZZ x;
    NTL::ZZ inv_x;
    NTL::ZZ_p random_ZZ_p;
    NTL::ZZ_p inv_random_ZZ_p;

    for(half_width = NUM_CHUNKS/2, k = 1; half_width > 1; half_width>>=1, k<<=1)
    {
        convert_arr_to_ZZ_p(random_ZZ_p, (uint32_t*)random_str);
        NTL::inv(inv_random_ZZ_p, random_ZZ_p);
        conv(x, random_ZZ_p);
        conv(inv_x, inv_random_ZZ_p);

        for(int i = 0; i < k; ++i)
        {
            int pos = (i<<1) + 1;
            for(int j = pos*half_width, q = 0; j < (pos+1)*half_width; ++j, ++q)
                x_values[j] = x_values[j] * x;
        }

        for(int i = 0; i < k; ++i)
        {
            int pos = (i<<1);
            for(int j = pos*half_width, q = 0; j < (pos+1)*half_width; ++j, ++q)
                x_values[j] = x_values[j] * inv_x;
        }

        random_ZZ_p *= random_ZZ_p;
        NTL::inv(inv_random_ZZ_p, random_ZZ_p);
        conv(x, random_ZZ_p);
        conv(inv_x, inv_random_ZZ_p);  

        convert_ZZ_to_scalar(sc_x, x);
        convert_ZZ_to_scalar(sc_inv_x, inv_x);

        // Get L
        secp256k1_eckey_pubkey_parse(&temp, proof_ptr, 33);
        secp256k1_gej_set_ge(&L, &temp);
        
        // Update x with L
        secp256k1_sha256_write(&sha256, proof_ptr, 33);
        secp256k1_sha256_finalize(&sha256, random_str);

        proof_ptr += 33;

        secp256k1_ecmult(&L, &L, &sc_x, NULL);

        // Get R
        secp256k1_eckey_pubkey_parse(&temp, proof_ptr, 33);
        secp256k1_gej_set_ge(&R, &temp);

        // Update x with R
        secp256k1_sha256_write(&sha256, proof_ptr, 33);
        secp256k1_sha256_finalize(&sha256, random_str);

        proof_ptr += 33;

        secp256k1_ecmult(&R, &R, &sc_inv_x, NULL);

        secp256k1_gej_add_var(&commitment, &commitment, &L, NULL);
        secp256k1_gej_add_var(&commitment, &commitment, &R, NULL);
    }

    NTL::ZZ a[2], b[2];
    NTL::ZZ ab(0);

    for(int i = 0; i < 2; ++i)
    {
        convert_arr_to_ZZ(a[i], (uint32_t*)proof_ptr);
        proof_ptr += 32;
        convert_arr_to_ZZ(b[i], (uint32_t*)proof_ptr);
        proof_ptr += 32;
        ab += a[i] * b[i];
    }

    secp256k1_gej P;
    ab = ab % GROUP_ORDER;

    convert_ZZ_to_scalar(c, ab);
    secp256k1_ecmult_const(&P, &u, &c, 256);

    secp256k1_gej prod_point;

    int count = 0;
    NTL::ZZ v;
    for(int i = 0; i < NUM_CHUNKS>>1; ++i)
    {
        int pos = (i<<1);
        v = (a[0] * x_values[pos]) % GROUP_ORDER;
        convert_ZZ_to_scalar(sc[count], v);
        ptp[count] = &generators[pos];
        count++;
    }

    for(int i = 0; i < NUM_CHUNKS>>1; ++i)
    {
        int pos = (i<<1)+1;
        v = (a[1] * x_values[pos]) % GROUP_ORDER;
        convert_ZZ_to_scalar(sc[count], v);
        ptp[count] = &generators[pos];
        count++;
    }

    vector<future<void>> res;
    ThreadPool *pool = new ThreadPool(MAX_NUM_THREADS_CLIENT);

    int start_pos = 0;

    for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
    {
        res.push_back(pool->enqueue([this, t, start_pos]() 
        {
            ecmult_multi_data_p data; 
            data.sc = &sc[start_pos];
            data.pt = &ptp[start_pos];

            secp256k1_ecmult_multi_var(&ctx->error_callback, scratch[t], &commitment_parts[t], &szero, ecmult_multi_callback_p, &data, NUM_CHUNKS/MAX_NUM_THREADS_CLIENT);
        }));
        start_pos += NUM_CHUNKS/MAX_NUM_THREADS_CLIENT;
    }
    
    for(auto &v: res) v.get();
    res.clear();

    for(int t = 0; t < MAX_NUM_THREADS_CLIENT; ++t)
        secp256k1_gej_add_var(&P, &P, &commitment_parts[t], NULL);

    secp256k1_ge r1, r2;
    secp256k1_ge_set_gej(&r1, &commitment);
    secp256k1_ge_set_gej(&r2, &P);
    ge_equals_ge(&r1, &r2); 

    cout << "BULLETPROOF PASSED." << endl;

    delete pool;
}
#else 
bool Client::verify_kzg_proof(uint8_t *kzg_proof)
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

    memcpy(commitment,  kzg_proof,     64);
    memcpy(proof_H,     kzg_proof+64,  64);
    memcpy(proof_point, kzg_proof+128, 32);
    memcpy(proof_claim, kzg_proof+160, 32);

    return static_cast<bool>(verify_proof(&gs_commitment, &gs_proof_H, &gs_proof_point, &gs_proof_claim));
}
#endif 

#endif
