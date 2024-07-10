#include "packet_capture.h"

void usage(const char *argv) {
    std::cout << "usage: %s interface/xxx.pcap" << std::endl;
}

int main(int argc, const char *argv[]) {
    if (argc != 2) {
        usage(argv[0]);
        return -1;
    }
    try {
        PacketCapture p(argv[1]);
        p.run();
        std::cout << PacketCapture::_num << std::endl;
        std::cout << "arp映射： IP地址  MAC地址" << std::endl;
        // for (auto &[ip, mac] : arp_map) //结构化绑定 C++17
        std::map<AddrIPv4, std::string> arp_table(PacketCapture::arp_map);
        for (const auto &pair : arp_table) {
            std::cout << pair.first.to_string() << "  " << pair.second.c_str() << std::endl;
        }
    } catch (const std::exception &e) {
        printf("exception ==> %s\n", e.what());
    }

    return 0;
}
