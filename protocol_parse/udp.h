#ifndef __UDP_H__
#define  __UDP_H__ 

#include "protocol.h"
#include "dns.h"

#define UDP_HEADER_SIZE         8       // upd报文头部字节长度

class Udp : public Protocol 
{
public:
    uint16_t _source_port {0};      // 源端口
    uint16_t _target_port {0};      // 目的端口
    uint16_t _total_size {0};       // 总长度
    uint16_t _check_sum {0};        // 校验值
    //void *_data{nullptr};           // 数据部分
    Dns _data; 
    Udp();
    ~Udp();

    bool check_total_size(uint32_t size); 
   
    const std::type_info &get_class_type_info();
    bool check_buffer_length(void *buffer, uint32_t size);
    int parse(void *buffer, uint32_t size);
    int opposite_byte();
    int debug_info();
};



#endif 
