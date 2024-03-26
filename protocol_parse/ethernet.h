#ifndef __ETHERNET_H__
#define __ETHERNET_H__ 

#include "base.h"
#include "protocol.h"

/** 暂时默认解析的以太网数据包无帧校验序列fcs字段 **/

#define ETHERNET_MAC_BYTE               6       // 以太网数据包MAC地址字节长度
#define ETHERNET_PREAMBLE_BYTE          7       // 以太网数据包前导码字节长度
#define ETHERNET_SFD_BYTE               1       // 以太网数据包 帧起始分隔（或叫做帧开始符）字节长度


#define ETHERNET_PREAMBLE_VALUE         0x55    // 以太网数据包前导码值
#define ETHERNET_SFD_VALUE              0xD5    // 以太网数据包SFD值

#define ETHERNET_HEADER_MIN_BYTE        14      // 以太网数据包包头最小长度，去除前导码和帧开始符
#define ETHERNET_HEADER_MAX_BYTE        ETHERNET_HEADER_MIN_BYTE + ETHERNET_PREAMBLE_BYTE + ETHERNET_SFD_BYTE      // 以太网数据包包头最大长度

#define ETHERNET_MIN_BYTE               60      // 以太网数据包最小长度，去除前导符和帧开始符
#define ETHERNET_MAX_BYTE               1522    // 以太网数据包最大长度,不计入帧检验序列FCS字段

class EthernetHeader : public Protocol 
{
public:
    u_char _preamble[ETHERNET_PREAMBLE_BYTE];   // 前导码
    u_char _sfd;                                // 帧开始符
    u_char _target_mac[ETHERNET_MAC_BYTE];      // 目的MAC地址 
    u_char _source_mac[ETHERNET_MAC_BYTE];      // 源MAC地址 
    uint16_t _type;                             // 类型字段，确定上层的协议

    EthernetHeader(bool is_opposite_byte);
    ~EthernetHeader();
    
    // 是否有前导码和帧开始符
    bool is_have_preamble_and_sfd(void *buffer, uint32_t size);
    
    // 协议类型
    bool is_protocol_type();

    bool check_buffer_length(void *buffer, uint32_t size);
    int parse(void *buffer, uint32_t size);
    int opposite_byte();
    int debug_info();
};

class Ethernet : public Protocol 
{
public:
    EthernetHeader _header;     // 以太网数据包头
    void *_data;                 // 以太网数据包数据区
    uint32_t _data_size;        // 数据包中数据长度

    Ethernet(bool is_opposite_byte);
    ~Ethernet();
    
    bool check_buffer_length(void *buffer, uint32_t size);
    int parse(void *buffer, uint32_t size);
    int opposite_byte();
    int debug_info();

};

#endif 




