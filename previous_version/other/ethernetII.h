#ifndef __ETHERNETII_H__
#define __ETHERNETII_H__
/*
    解析以太网协议
*/
#include <net/ethernet.h>
#include <netinet/in.h>

#include "exception.h"
// 解析以太网协议
// void parse() {
//     // MAC 地址的字节顺序是由网络硬件按照 IEEE 标准处理的，不需要转换为主机字节序。
//     // 只需要将 type 字段从网络字节序转换为主机字节序，而目的和源 MAC 地址字段则保持原样。
//     memcpy(&(_dst), _data, ETHERNET_MAC_LEN);
//     memcpy(&(_src), _data + ETHERNET_MAC_LEN, ETHERNET_MAC_LEN);
// }

class EthernetII {
public:
    enum {
        ETHERNET_MAC_LEN = 6,     // 以太网协议中地址长度， 单位字节
        ETHERNET_HEADER_LEN = 14  // 以太网帧头部最小长度 DST(6B) + SRC(6B) + TYPE(2B)
    };

    /*
        @param: packet - 报文起始地址
        @param: size - 数据的长度
    */
    EthernetII(const u_char *packet, uint32_t size) : _data(packet), _data_size(size) {
        if (size < ETHERNET_HEADER_LEN)  // 检查size的是否有效
            throw std::invalid_argument("invalid size");
        parse();  // 开始解析
    }

    // 解析以太网协议
    void parse() {
        // MAC 地址的字节顺序是由网络硬件按照 IEEE 标准处理的，不需要转换为主机字节序。
        // 只需要将 type 字段从网络字节序转换为主机字节序，而目的和源 MAC 地址字段则保持原样。
        memcpy(&(_dst), _data, ETHERNET_MAC_LEN);
        memcpy(&(_src), _data + ETHERNET_MAC_LEN, ETHERNET_MAC_LEN);
    }

    const u_char *dst_mac() const noexcept {
        return _dst;
    }

    const u_char *src_mac() const noexcept {
        return _src;
    }

    const char *type_string() const {
        switch (type()) {
        case ETHERTYPE_IP:  // 0x0800
            return "IPv4";
        case ETHERTYPE_ARP:  // 0x0806
            return "ARP";
        case ETHERTYPE_REVARP:  // 0x0835
            return "RARP";
        case ETHERTYPE_IPV6:  // 0x86DD
            return "IPv6";
        default:
            return "";
        }
    }

    bool is_ipv4() const {
        return type() == 0x0800;
    }
    bool is_ipv6() const {
        return type() == 0x86DD;
    }
    bool is_arp() const {
        return type() == 0x0806;
    }

    // 输出以太网协议内容
    void debug_info() {
        auto print_byte = [](u_char *buf, int size) {
            for (int index = 1; index < size; index++)
                printf("-%02X", buf[index]);
        };

        printf(" src_mac = %02X", _src[0]);
        print_byte(_src, ETHERNET_MAC_LEN);
        printf(" -> dst_mac = %02X", _dst[0]);
        print_byte(_dst, ETHERNET_MAC_LEN);
        printf(" | %s\n", type_string());
    }
    // 返回上层协议有效载荷（即数据）的大小
    uint32_t payload_size() const noexcept {
        return _data_size - ETHERNET_HEADER_LEN;
    }
    // 返回上层协议有效载荷（即数据）的起始地址
    const uint8_t *payload() const noexcept {
        return _data + ETHERNET_HEADER_LEN;
    }
    // ethernerII上层协议类型
    uint16_t type() const noexcept {
        return ntohs(*(uint16_t *)(_data + ETHERNET_MAC_LEN * 2));
    }

private:
    u_char _dst[ETHERNET_MAC_LEN]{0};  // 目标mac地址
    u_char _src[ETHERNET_MAC_LEN]{0};  // 源mac地址
    const uint8_t *_data;                 // 数据的起始地址
    uint32_t _data_size;               // 数据包的大小
};

#endif  // __ETHERNETII_H__
