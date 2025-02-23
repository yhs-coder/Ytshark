#ifndef __IP_H__ 
#define __IP_H__ 

#include "base.h"
#include "protocol.h"

#define IP_HEADER_FIX_SIZE                      20          // IP报文头部固定部分字节长度
#define IP_VERSION_4                            4           // IPV4版本
#define IP_VERSION_6                            6           // IPV6版本
#define IS_IP_VERSION(version)                  ((version) == IP_VERSION_4 || (version) == IP_VERSION_6)
#define IP_HEADER_SIZE_BYTE_UNIT                4           // IP数据包首部长度值单位
#define IP_FRAGMENT_OFFSET_BYTE_UNIT            8           // IP数据包片偏移值单位
#define IP_FLAG_IS_FRAGMENT_GETTER(byte)        (((byte) & 0x40) > 0)   // 是否分片标志获取， bool
#define IP_FLAG_IS_MORE_FRAGMENT_GETTER(byte)   (((byte) & 0x20) > 0)   // 是否更换分片标志获取， bool
#define IP_FRAGMENT_OFFSET_GETTER(value)        (((value) & 0x1FFF))    // 片偏移，bool 

class Ip : public Protocol 
{
public:
    uint8_t _version;               // ip版本协议号, 大小为H4bit
    uint8_t _header_len;            // 首部字节长度(4bit)，以4字节为一个单位
    u_int8_t _service_type;         // 区分服务
    uint16_t _total_len;            // 总长度
    uint16_t _identification;       // 标识
    uint8_t _flags;                 // 分片标志位,3bit
    uint16_t _fragment_offset;      // 片偏移，13bit,以8字节为单位
    uint8_t _ttl;                   // 生存时间
    uint8_t _protocol;              // 数据上层的协议类型
    uint16_t _checksum;             // 首部校验和
    uint32_t _source_ip;            // 源ip
    uint32_t _target_ip;            // 目的ip
    //Protocol *_data;                // 数据部分，（上层数据包）
    void *_data;
    Ip();
    ~Ip();

    const std::type_info &get_class_type_info()
    {
        return typeid(*this);
    }
    bool is_protocol_type();
    bool check_buffer_length(void *buffer, uint32_t size);
    int parse(void *buffer, uint32_t size);
    int opposite_byte();
    int debug_info();
};


#endif 
