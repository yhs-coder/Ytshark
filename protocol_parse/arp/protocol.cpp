#include "protocol.h"

Protocol::~Protocol()
{
}

int get_endian()
{
    uint32_t value = 0x1A2B3C4D;
    // 判断大小端
    return (*((char*)(&value)) == 0x1A ? BIG_ENDIAN : LITTLE_ENDIAN);
}

/*
 * @return 网络层协议名
 * */

const char *get_network_layer_protocol_name(uint32_t type)
{
    switch(type)
    {
        case ETHERTYPE_IP:
            return "IPV4";
        case ETHERTYPE_ARP:
            return "ARP";
        case ETHERTYPE_REVARP:
            return "Reverse ARP";
        case ETHERTYPE_VLAN:
            return "VLAN";
        case ETHERTYPE_IPV6:
            return "IPV6";
        case ETHERTYPE_LOOPBACK:
            return "LOOPBACK";
        default:
            return "unknown";
    }
}


/*
 * @return 传输层协议名
 * */
const char *get_transport_layer_protocol_name(uint32_t type)
{
    switch(type)
    {
        case TRANSPORT_LAYER_PROTOCOL_ICMP:
            return "ICMP";
        case TRANSPORT_LAYER_PROTOCOL_TCP:
            return "TCP";
        case TRANSPORT_LAYER_PROTOCOL_UDP:
            return "UDP";
        default:
            return "unknown";
    }
}
