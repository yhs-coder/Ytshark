#ifndef __ARP_PACKET_H__
#define __ARP_PACKET_H__

#include <netinet/in.h>
#include <iomanip>
#include "exception.h"
#include "byte.h"
/*
模块功能：解析arp数据包
arp协议报文格式
---------------------------------------------------------------------------------------------------------------------
| 硬件类型 | 协议类型 | 硬件地址长度 | 协议地址长度 | 操作码 | 发送方硬件地址 | 发送方协议地址 | 目标硬件地址 | 目标协议地址 |
---------------------------------------------------------------------------------------------------------------------
    2B        2B         1B             1B          2B          6B              4B          6B              4B
*/
// const unsigned int ARP_HEADER_LEN = 28; // arp首部长度
// const unsigned int MAC_LEN = 6;         // mac地址长度，单位字节
// const unsigned int IP_LEN = 4;          // ip地址长度，单位字节

// arp协议中 opcode字段，即操作类型

const uint16_t ARP_REPLY = 2;    // arp应答/响应
const uint16_t ARP_RREQUEST = 3; // rarp请求
const uint16_t ARP_RREPLY = 4;   // rarp应答/响应
const uint16_t ARP_REQUEST = 1;  // arp请求

struct AddrIPv4 : in_addr
{
    AddrIPv4(uint32_t addr)
    {
        s_addr = addr;
    }
    std::string to_string() const
    {
        const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&s_addr);
        return std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) + "." +
               std::to_string(bytes[2]) + "." + std::to_string(bytes[3]);
    }

    bool operator<(const AddrIPv4 &r) const noexcept
    {
        return s_addr < r.s_addr;
    }
};

class ArpPacket
{
public:
    enum : const unsigned int
    {
        ARP_HEADER_LEN = 28, // arp首部长度
        MAC_LEN = 6,         // mac地址长度，单位字节
        IP_LEN = 4           // ip地址长度，单位字节
    };

    ArpPacket(const byte *data, uint32_t size) : _data(data)
    {
        _hardware_type = _protocol_type = _op_type = 0;
        _hardware_size = _protocol_size = 0;
        if (size < ARP_HEADER_LEN)
            throw std::invalid_argument("invalid ARP packet");
    }

    void parse()
    {
        _hardware_type = as_host<uint16_t>(_data);
        _data += sizeof(_hardware_type);
        _protocol_type = as_host<uint16_t>(_data);
        _data += sizeof(_protocol_type);
        _hardware_size = as_host<byte>(_data);
        _data += sizeof(_hardware_size);
        _protocol_size = as_host<byte>(_data);
        _data += sizeof(_protocol_size);
        _op_type = as_host<uint16_t>(_data);
        _data += sizeof(_op_type);

        // 拷贝mac地址和ip地址
        memcpy(&(_source_mac), _data, MAC_LEN);
        _data += MAC_LEN;
        memcpy(&(_source_ip), _data, IP_LEN);
        _data += IP_LEN;
        memcpy(&(_target_mac), _data, MAC_LEN);
        _data += MAC_LEN;
        memcpy(&(_target_ip), _data, IP_LEN);
        _data += IP_LEN;
    }

    AddrIPv4 source_ip() const noexcept
    {
        return AddrIPv4{_source_ip};
    }
    AddrIPv4 target_ip() const noexcept
    {
        return AddrIPv4{_target_ip};
    }

    const byte *source_mac() const noexcept
    {
        return _source_mac;
    }
    const byte *target_mac() const noexcept
    {
        return _target_mac;
    }

    uint16_t op_type() const noexcept
    {
        return _op_type;
    }

    // 封装函数来格式化 MAC 地址
    void static format_mac(const byte *mac)
    {
        auto print_byte = [](const byte *buf, int size)
        {
            for (int index = 1; index < size; index++)
                printf("-%02X", buf[index]);
        };
        printf("%02X", mac[0]);
        print_byte(mac, MAC_LEN);
    }
    std::string format_mac_address(const unsigned char *mac)
    {
        char buffer[20];
        snprintf(buffer, sizeof(buffer), "%02X-%02X-%02X-%02X-%02X-%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(buffer);
    }

    void debug_info()
    {
        std::cout << std::hex << std::showbase;
        std::cout << "hardware_type: " << _hardware_type << std::endl;
        std::cout << "protocol_type: " << _protocol_type << std::endl;
        std::cout << "hardware_size: " << static_cast<int>(_hardware_size) << std::endl;
        std::cout << "protocol_size: " << static_cast<int>(_protocol_size) << std::endl;
        std::cout << "op_type: " << _op_type << std::endl;
        std::cout << "source_mac: " << format_mac_address(_source_mac) << std::endl;
        std::cout << "source_ip: " << source_ip().to_string() << std::endl;
        std::cout << "target_mac: " << format_mac_address(_target_mac) << std::endl;
        std::cout << "target_ip: " << target_ip().to_string() << std::endl;
    }

private:
    const byte *_data;            // arp报文起始地址
    uint16_t _hardware_type;      // 硬件类型，对于以太网，此值为1
    uint16_t _protocol_type;      // 协议类型, 该字段指出映射的协议地址类型， 对于IPv4地址，该值为OxO800
    byte _hardware_size;          // 硬件大小，指出硬件地址的字节数
    byte _protocol_size;          // 协议大小，指出协议地址的字节数
    uint16_t _op_type;            // 操作类型，指出操作的是arp/rarp请求，或者arp/rarp应答
    byte _source_mac[MAC_LEN]{0}; // 发送方mac地址
    uint32_t _source_ip{0};       // 发送方ip地址
    byte _target_mac[MAC_LEN]{0}; // 目标mac地址
    uint32_t _target_ip{0};       // 目标ip地址
};

#endif // __ARP_PACKET_H__