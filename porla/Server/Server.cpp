#include "Server.hpp"

int main(int argc, char **argv)
{
    Server server;
    
    server.initialize();

    server.self_test();

    return 0;
}


