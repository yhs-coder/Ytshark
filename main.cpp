#include "packet_capture.h"

void usage(const char* argv)
{
    std::cout << "usage: %s interface" << std::endl;
}

int main(int argc, const char* argv[])
{
    if (argc != 2) 
    {
        usage(argv[0]);
        return -1;
    }

    PacketCapture p(argv[1]);
    p.run();
    
    std::cout << "=======================================" << std::endl;
    return 0;
}
