#ifndef __ARP_H__
#define __ARP_H__ 

#include "base.h"
#include "protocol.h"

#define ARP_HEADER_SIZE                                 8       // ARP报文头部字节长度
#define ARP_DATA_SIZE(hardware_size, protocol_size)     (2 * (hardware_size) + 2 * (protocol_size))                         // arp报文内容字节长度
#define ARP_TOTAL_SIZE(hardware_size, protocol_size)    (ARP_DATA_SIZE(hardware_size, protocol_size) + ARP_HEADER_SIZE)     // arp报文总长度
#define ARP_TYPE_REQUEST                                1       // arp请求报文
#define ARP_TYPE_RESPOND                                2       // arp应答报文
#define IS_ARP_TYPE(type)                               ((type) == ARP_TYPE_REQUEST || (TYPE) == ARP_TYPE_RESPOND)

// arp报文封装在以太网报文中 
class ArpMacAndIp : public Protocol 
{
public:
    uint8_t _source_mac[MAC_COMMON_SIZE] {0};   // 发送方mac地址
    uint32_t _source_ip {0};                    // 发送方ip地址
    uint8_t _target_mac[MAC_COMMON_SIZE] {0};   // 目标mac地址
    uint32_t _target_ip {0};                    // 目标ip地址

    ArpMacAndIp();
    ~ArpMacAndIp();
    
    const std::type_info &get_class_type_info();
    bool check_buffer_length(void *buffer, uint32_t size);
    int parse(void *buffer, uint32_t size);
    int opposite_byte();
    int debug_info();
};

class Arp : public Protocol
{
public:
    uint16_t _hardware_type;    // 硬件类型
    uint16_t _protocol_type;    // 协议类型
    uint8_t _hardware_size;     // 硬件大小
    uint8_t _protocol_size;     // 协议大小
    uint16_t _op_type;          // 操作类型
    Protocol *_data;            // arp数据部分

    Arp();
    ~Arp();

    bool is_hardware_type();
    bool is_protocol_type();
    bool is_operation_type();
    bool check_total_size(uint32_t size);
    Protocol *new_arp_data_class();
    static const char *get_arp_operation_name(uint32_t type);

    const std::type_info &get_class_type_info();
    bool check_buffer_length(void *buffer, uint32_t size);
    int parse(void *buffer, uint32_t size);
    int opposite_byte();
    int debug_info();

};


#endif 
