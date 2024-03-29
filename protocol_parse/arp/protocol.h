#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__ 

#include "base.h"

#define STR(x)                                  #x
#define STR_CONTACT(a, b)                       a##b


#define IP_GETTER_RIRST(value)                  ((value) >> 24)
#define IP_GETTER_SECOND(value)                 (((value) & 0x00FF0000) >> 16)
#define IP_GETTER_THIRD(value)                  (((value) & 0x0000FF00) >> 8)
#define IP_GETTER_FOURTH(value)                 ((value) & 0x000000FF)

#define MAC_COMMON_SIZE                         6       // mac地址内存常用存储字节长度
#define IP_COMMON_SIZE                          4       // ip地址内存常用存储字节长度



/* 传输层协议类型  */
#define TRANSPORT_LAYER_PROTOCOL_ICMP           1
#define TRANSPORT_LAYER_PROTOCOL_TCP            6
#define TRANSPORT_LAYER_PROTOCOL_UDP            17

#define PARSE_SUCCESS                           0       // 解析完成       
/* 解析pcap文件错误码 */ 
#define PCAP_PARSE_ERROR_LOAD_FILE              -1      // 加载pcap文件出错
#define PCAP_PARSE_ERROR_MAP_GET_BUFFER         -2      // 获取映射内存的文件内容出错
#define PCAP_PARSE_ERROR_HEADER_LENGTH          -11     // pcap文件头不完整
#define PCAP_PARSE_ERROR_MAGIC                  -12     // 文件头标识错误
#define PCAP_PARSE_ERROR_PACKET_HEADER_LENGTH   -21     // pcap数据包头不完整

/* 解析以太网数据包错误码  */
#define ETHERNET_PARSE_ERROR_BASE               -100    // 以太网数据包解析错误
#define ETHERNET_PARSE_ERROR_MIN_LENGTH         -101    // 以太网数据包不完整
#define ETHERNET_PARSE_ERROR_PROTOCOL_TYPE      -102    // 以太网数据包协议类型错误 

/* 解析IP数据包错误码  */
#define IP_PARSE_ERROR_HEADER_MIN_LENGTH        -151    // IP数据包头不完整
#define IP_PARSE_ERROR_PROTOCOL_TYPE            -152    // IP数据包协议类型错误
#define IP_PARSE_ERROR_VERSION                  -153    // IP数据包版本类型错误
#define IP_PARSE_ERROR_LENGTH                   -154    // IP数据包不完整

/* 解析arp数据包错误码 */
#define ARP_PARSE_ERROR_HEADER_LENGTH           -201    // arp数据包头部不完整
#define ARP_PARSE_ERROR_HARDWARE_TYPE           -202    // arp数据包硬件类型错误
#define ARP_PARSE_ERROR_PROTOCOL_TYPE           -203    // arp数据包协议类型错误
#define ARP_PARSE_ERROR_DATA_LENGTH             -204    // arp数据包内容不完整

/*
#define PCAP_PARSE_ERROR_PACKET_DATA    -22     // 获取pcap数据包内容出错

#define PCAP_HEADER_BYTES               24      // pcap文件头长度为24字节
#define PCAP_PACKET_HEADER_BYTES        16      // 数据包头长度为16字节
*/

// 协议类
class Protocol 
{
public:
    bool _is_opposite_byte;  // 是否需要大小端字节倒序
    uint32_t _size;         // 数据总大小

    Protocol(bool is_opposite)
        : _is_opposite_byte(is_opposite)
        , _size(0)
    {}
    virtual ~Protocol();
    // 提供统一接口
    
    virtual const std::type_info &get_class_type_info() = 0;

    // 检查缓冲区长度
    virtual bool check_buffer_length(void *buffer, uint32_t size) = 0;
    // 解析缓冲区buffer中size个字节的数据
    virtual int parse(void *buffer, uint32_t size) = 0;
    // 转换字节序
    virtual int opposite_byte() = 0;
    // 调试信息
    virtual int debug_info() = 0;
};

// 获取字节序模式
int get_endian();
const char *get_network_layer_protocol_name(uint32_t type);
const char *get_transport_layer_protocol_name(uint32_t type);
const char *get_arp_operator_name(uint32_t type);


#endif /* __PROTOCOL_H__ */
