#ifndef __IPV4_PACKET_H
#define __IPV4_PACKET_H
#include "exception.h"
#include "byte.h"
#include <arpa/inet.h>
#include "protocol_type.h"
#include "addr_ipv4.h"
/*
IPV4
+-------+-----------+---------------+-------------------------+
| 4 bit |   4 bit   |    8 bit      |          16 bit         |
+-------+-----------+---------------+-------------------------+
|version|head length|  TOS/DS_byte  |        total length     |
+-------------------+--+---+---+----+-+-+-+-------------------+
|          identification           | |D|M|    offset         |
+-------------------+---------------+-+-+-+-------------------+
|       ttl         |     protocal  |         checksum        |
+-------------------+---------------+-------------------------+
|                   source ip address                         |
+-------------------------------------------------------------+
|                 destination ip address                      |
+-------------------------------------------------------------+
 IP Flag字段格式
0     1    2
+---+----+----+
| 0 | DF | MF |
+---+----+-----+
Bit 0: 保留位，必须为0。
Bit 1: DF（Don't Fragment），能否分片位，0表示可以分片，1表示不能分片。
Bit 2: MF（More Fragment），表示是否该报文为最后一片，0表示最后一片，1代表后面还有。
*/

class IPv4Packet
{
    enum
    {
        IPV4_HEADER_LEN = 20
    };

public:
    IPv4Packet(const uint8_t *data, uint32_t size) : _data(data), _data_size(size)
    {
        if (size <= IPV4_HEADER_LEN)
            throw std::invalid_argument("invalid IP packet");
        _version = _header_len = _service_type = 0;
        _total_len = _identification = _checksum = 0;
        _flags = _ttl = _protocol = 0;
        _fragment_offset = 0;
        _source_ip = _target_ip = 0;
    }
    void parse()
    {
        /** 4byte  **/
        // 读取第一个字节，并通过位操作提取出这个字节中的高4位
        // & 0xf表示对移动后的结果进行按位与操作，目的是保留低4位，将高4位清零
        // _version大小为4bit,网络字节序，所以data[0] == _version(4bit)  _header_len(4bit)
        _version = (_data[0] >> 4) & 0xf;
        _header_len = (_data[0] & 0xf) * 4;
        _service_type = _data[1];
        // _total_len = ntohs(*(uint16_t *)(&_data[2]));
        _total_len = ntohs(*(uint16_t *)(_data + 2));

        /** 4bytes **/
        // _identification = ntohs(*(uint16_t *)(&_data[4]));
        _identification = ntohs(*(uint16_t *)(_data + 4));
        _flags = (_data[6] >> 5) & 0b00000111; // 提取分片标志位
        // 0x1fff == 0001 1111 1111 1111, 网络字节序，flags在高3位，000除掉
        // _fragment_offset = ntohs(*(uint16_t *)(&data[6])) & 0x1fff;
        _fragment_offset = ntohs(*(uint16_t *)(_data + 6)) & 0x1fff;

        /** 4bytes **/
        _ttl = _data[8];
        _protocol = _data[9];
        // _checksum = ntohs(*(uint16_t *)(&_data[10]));
        _checksum = ntohs(*(uint16_t *)(_data + 10));

        /** 4bytes **/
        // _source_ip = ntohl(*(uint32_t *)(&_data[12]));
        _source_ip = *(uint32_t *)(_data + 12);
        // _target_ip = ntohl(*(uint32_t *)(&_data[16]));
        _target_ip = *(uint32_t *)(_data + 16);
    }

    AddrIPv4 source_ip() const noexcept
    {
        return AddrIPv4{_source_ip};
    }

    AddrIPv4 target_ip() const noexcept
    {
        return AddrIPv4{_target_ip};
    }

    // 能否分片位，0表示可以分片，1表示不能分片。
    bool dont_fragment() const noexcept
    {
        return _flags & 0b00000010;
    }

    // 0表示最后一片，1代表后面还有
    bool more_fragment() const noexcept
    {
        return _flags & 0b00000010;
    }

    // 返回ip协议上层数据
    const uint8_t *payload() const noexcept
    {
        return _data + IPV4_HEADER_LEN;
    }

    uint32_t size() const noexcept
    {
        return _data_size - IPV4_HEADER_LEN;
    }

    // 输出ip协议报文内容
    void debuf_info() const noexcept
    {
        // 使用printf格式化输出uint8_t类型的数据
        printf("version: %u\nheader_len: %u bytes\nservice type: %#x\ntotal len: %u\n",
               _version, _header_len, _service_type, _total_len);
        printf("identification: %u\nflags: %u\nfragment offset: %u\n",
               _identification, _flags, _fragment_offset);
        printf("ttl: %u\nprotocol: %u (%s)\nchecksum: %#x\n", _ttl, _protocol, to_string((ProtocolType)_protocol), _checksum);
        printf("source_ip: %s\n", source_ip().to_string().c_str());
        printf("target_ip: %s\n", target_ip().to_string().c_str());
    }

private:
    uint8_t _version;          // ip版本协议号, 大小为4bit
    uint8_t _header_len;       // 首部字节长度(4bit)，以4字节为一个单位
    uint8_t _service_type;     // 区分服务
    uint16_t _total_len;       // 总长度
    uint16_t _identification;  // 标识
    uint8_t _flags;            // 分片标志位,3bit
    uint16_t _fragment_offset; // 片偏移，13bit,以8字节为单位
    uint8_t _ttl;              // 生存时间
    uint8_t _protocol;         // 数据上层的协议类型
    uint16_t _checksum;        // 首部校验和
    uint32_t _source_ip;       // 源ip
    uint32_t _target_ip;       // 目的ip
    const byte *_data;         // ip报文起始地址
    uint32_t _data_size;       // ip数据包总大小
};

#endif // __IPV4_PACKET_H