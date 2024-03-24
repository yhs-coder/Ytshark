#include "packet_capture.h"


PacketCapture::PacketCapture(const char* device)
{
    if (!(_handle = pcap_open_live(device, snaplen, 1, 0, _errbuf)))
    {
        printf("error: pcap_open_live():%s\n",_errbuf);
    }
}

PacketCapture::~PacketCapture()
{
    if (_handle != nullptr)
        close();
}


void process_packet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    // 打印抓取的数据包长度和实际发送的数据包长度
    std::cout << "caplen: " << pkthdr->caplen << "\t len: " << pkthdr->len << std::endl;
    sleep(1);
}

void PacketCapture::run()
{
    // 获取数据包
    if (pcap_loop(_handle, -1, process_packet, nullptr) < 0)
        std::cout << "error: pcap_loop()" << std::endl;
}


void PacketCapture::close()
{
    pcap_close(_handle);
}

