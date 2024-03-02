#pragma once
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdint.h>


// 句柄定义
typedef struct dpi_result {
    void* pcap_handle;          // 存储pcap_t类型句柄
    unsigned int ether_count;   // 以太网报文数量
    unsigned int ip_count;      // ip报文数量
    unsigned int tcp_count;     // tcp报文数量
    unsigned int udp_count;     // udp报文数量
    unsigned int ssh_count;     // ssh报文数量
}dpi_result;


// 定义报文的解析信息
typedef struct dpi_pkt {
    uint32_t ether_len;                 // 以太网报文长度
    struct ether_header* ether_packet;  // 以太网报文的地址
    uint32_t ip_len;                    // ip报文长度
    char* ip_packet;                    // ip报文的地址  
    uint32_t tcp_len;                   // tcp报文长度
    char* tcp_packet;                   // tcp报文的地址 
    uint32_t udp_len;                   // udp报文长度
    char* udp_packet;                   // udp报文的地址    
}dpi_pkt;


// 初始化
// pcapfile :要处理的pcap文件
// 返回值:设计一个句柄，这个句柄包含了结果
// 成功返回非空的指针，失败返回NULL
dpi_result* dpi_init(const char* pcapfile);

// 业务处理
// 自动执行报文解析
void dpi_loop(dpi_result* res);

// 释放资源
void dpi_destroy(dpi_result* res);
