#include "Client.hpp"

int main(int argc, char **argv)
{    
    Client client;

    int num_data_blocks = 1024;

    if (argc > 1)
        num_data_blocks = atoi(argv[1]);

    client.initialize(num_data_blocks);
    
    client.self_test();

    return 0;
}


