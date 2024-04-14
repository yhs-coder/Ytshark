#include "packet_capture.h"

uint32_t PacketCapture::_num = 0;
std::map<AddrIPv4, std::string> PacketCapture::arp_map{};

PacketCapture::PacketCapture(const char *handle)
{
    // if (!(_handle = pcap_open_live(handle, snaplen, 1, 0, _errbuf)))
    // {
    //     printf("error: pcap_open_live():%s\n", _errbuf);
    // }
    _handle = pcap_open_offline(handle, _errbuf);
}

PacketCapture::~PacketCapture()
{
    if (_handle != nullptr)
        close();
}

void process_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    PacketCapture::_num++;
    // 打印抓取的数据包长度和实际发送的数据包长度
    // std::cout << "caplen: " << pkthdr->caplen << "\t len: " << pkthdr->len << std::endl;
    TimeStamp ts;
    printf("%d\t", PacketCapture::_num);
    ts.show_time(pkthdr);

    EthernetII ethernet(packet, ts.caplen(pkthdr));
    std::cout << ethernet.type_string() << std::endl;
    // ethernet.debug_info();
    if (ethernet.is_arp())
    {
        std::cout << "==============================================" << std::endl;
        ArpPacket arp(ethernet.payload(), ethernet.payload_size());
        arp.parse();
        auto source_ip = arp.source_ip().to_string();
        auto target_ip = arp.target_ip().to_string();

        switch (arp.op_type())
        {
        case ARP_REQUEST:
        {
            std::cout << "[ARP请求] " << source_ip << "(";
            arp.format_mac(arp.source_mac());
            std::cout << ") 查询 " << target_ip << " 的MAC地址" << std::endl;
        }
        break;
        case ARP_REPLY:
        {
            std::cout << "[ARP响应] " << target_ip << "(";
            arp.format_mac(arp.target_mac());
            std::cout << ") 回复 " << source_ip << "(";
            arp.format_mac(arp.source_mac());
            std::cout << ") ：" << target_ip << " 的MAC地址在我这里" << std::endl;
        }
        break;
        default:
            break;
        }
        // arp.debug_info();
        PacketCapture::arp_map.emplace(arp.source_ip(), arp.format_mac_address(arp.source_mac()));
    }
    // std::cout << "arp映射： IP地址  MAC地址" << std::endl;
    // // for (auto &[ip, mac] : arp_map) //结构化绑定 C++17
    // for (const auto &pair : arp_map)
    // {
    //     std::cout << pair.first.to_string() << pair.second.c_str() << std::endl;
    // }
    // sleep(1);
}

void PacketCapture::run()
{
    // 获取数据包
    if (pcap_loop(_handle, -1, process_packet, nullptr) < 0)
        throw IOException("pcap_loop");
}

void PacketCapture::close()
{
    pcap_close(_handle);
}
