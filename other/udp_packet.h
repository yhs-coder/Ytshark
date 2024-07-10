#ifndef __UDP_PACKET_H__
#define __UDP_PACKET_H__

/*
+---------------------+---------------------+
|        16 bit       |        16 bit       |
+---------------------+---------------------+
|    source port      |   destination port  |
+---------------------+---------------------+
| data package length |       checksum      |
+---------------------+---------------------+
*/
#include "exception.h"
#include "byte.h"
class UdpPacket
{
public:
    enum
    {
        // udp首部长度固定8字节
        UDP_HEADER_LEN = 8
    };
    UdpPacket(const uint8_t *data, uint32_t size) : _data(data), _data_size(size)
    {
        if (size <= UDP_HEADER_LEN)
            throw std::invalid_argument("invalid");
    }
    void parse()
    {
        _source_port = as_host<uint16_t>(_data);
        _target_port = as_host<uint16_t>(_data + 2);
        _total_size = as_host<uint16_t>(_data + 4);
        _check_sum = as_host<uint16_t>(_data + 6);
    }

    uint16_t source_port() const noexcept
    {
        return _source_port;
    }
    uint16_t target_port() const noexcept
    {
        return _target_port;
    }

    // 返回udp报文负载数据 起始地址
    const uint8_t *payload() const noexcept
    {
        return _data + UDP_HEADER_LEN;
    }

    // 返回udp报文负载数据大小
    uint32_t payload_size() const noexcept
    {
        return _data_size - UDP_HEADER_LEN;
    }

    bool is_dns() const
    {
        return _source_port == 53 || _target_port == 53;
    }

    // 输出udp报文内容
    void debug_info() const
    {
        printf("source_port: %u\ntarget_port: %u\n", _source_port, _target_port);
        printf("total_size: %u\ncheck_sum: %#x\n", _total_size, _check_sum);
    }

private:
    uint16_t _source_port{0}; // 源端口
    uint16_t _target_port{0}; // 目的端口
    uint16_t _total_size{0};  // 总长度
    uint16_t _check_sum{0};   // 校验值
    const uint8_t *_data;     // udp数据包起始地址
    uint32_t _data_size;      // udp数据包总大小
};

#endif // __UDP_PACKET_H__