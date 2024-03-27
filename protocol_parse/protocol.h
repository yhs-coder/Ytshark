#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__ 

#include "base.h"

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

    // 提供接口
    
    // 检查缓冲区长度
    virtual bool check_buffer_length(void *buffer, uint32_t size) = 0;
    // 解析缓冲区buffer中size个字节的数据
    virtual int parse(void *buffer, uint32_t size) = 0;
    // 转换字节序
    virtual int opposite_byte() = 0;
    // 调试信息
    virtual int debug_info() = 0;
};

#endif /* __PROTOCOL_H__ */
