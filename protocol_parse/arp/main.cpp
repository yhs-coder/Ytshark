#include "base.h"
#include "map_file.h"
#include "pcap.h"
#include "arp.h"
#include <map>

int opposite_int_order(int value)
{
    return OPPOSIZE_BYTE_ORDER(value);
}

void arp_ip_to_mac(std::map<uint32_t, u_char*>&arp_map, Arp &arp_pack)
{
    if (arp_pack._data != nullptr && arp_pack._data->get_class_type_info() == typeid(ArpMacAndIp))
    {
        ArpMacAndIp *arp_mac_ip = (ArpMacAndIp*)arp_pack._data;
        switch(arp_pack._op_type)
        {
            case ARPOP_REQUEST:
                arp_map.insert(std::map<uint32_t, u_char*>::value_type(arp_mac_ip->_source_ip, arp_mac_ip->_source_mac));
                arp_map.insert(std::map<uint32_t, u_char*>::value_type(arp_mac_ip->_target_ip, arp_mac_ip->_target_mac));
                break;
            case ARPOP_REPLY:
                arp_map.insert(std::map<uint32_t, u_char*>::value_type(arp_mac_ip->_source_ip, arp_mac_ip->_source_mac));
                arp_map.insert(std::map<uint32_t, u_char*>::value_type(arp_mac_ip->_target_ip, arp_mac_ip->_target_mac));
                break;
            default:
                return;
        }
    }
}

int main()
{
    //char file_name[] = "/home/yang/do_wireshark/TSD/protocol_parse/day3.pcap";
    char file_name[] = "./day8.pcap"; 
    int error_code = 0;
    std::map<uint32_t, u_char*> arp_map;
    PcapFile pcap_file;
    error_code = pcap_file.load_file(file_name);
    if (error_code != 0)
    {
        printf("load file error: %d, %s\n",error_code, strerror(error_code));
        return -1;
    }
    error_code = pcap_file.parse();
    if (error_code != PARSE_SUCCESS)
    {
        printf("parse pcap file error: %d\n",error_code);
        return -1;
    }
    // 打印出pcap头文件的内容
    pcap_file._file_header.debug_info();
    printf("packet amout = %d\n",(int)pcap_file._packets.size());
    // 遍历vector
    for (auto value : pcap_file._packets)
    {
        value->debug_info();
        Ethernet &ethernet_pack = value->ethernet;
        if (ethernet_pack._data != nullptr && ethernet_pack._data->get_class_type_info() == typeid(Arp))
            arp_ip_to_mac(arp_map, *((Arp*)(ethernet_pack._data)));
    }
    printf("\n, ip地址 => mac地址\n");
    for (std::map<uint32_t, u_char*>::iterator it = arp_map.begin(); it != arp_map.end(); it++)
    {
        uint32_t ip = it->first;
        printf("%d.%d.%d.%d  ", IP_GETTER_RIRST(ip), IP_GETTER_SECOND(ip),
                IP_GETTER_THIRD(ip),IP_GETTER_FOURTH(ip));
        printf("%02X",it->second[0]);
        for (int index = 1; index < MAC_COMMON_SIZE; index++)
            printf("-%02X",it->second[index]);
        printf("\n");
        
    }
    return 0;
}
