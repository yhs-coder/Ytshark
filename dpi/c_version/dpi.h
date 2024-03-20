#pragma once
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "dpi_list.h"

// 日志调试模块

// ...表示宏可以接收可变数量的参数
// do{...}while(0)是常见的宏定义技巧，用于创建一个代码块
// 即使在宏扩展时只有单个语句也不会产生副作用
// __VA_ARGS__ 是一个宏参数，它在宏定义中用来表示所有传递给宏的参数
#define DPI_LOG_DEBUG(...)            \
    do                                \
    {                                 \
        fprintf(stderr, __VA_ARGS__); \
    } while (0)
// #undef DPI_LOG_DEBUG 取消宏定义
#define DPI_LOG_INFO(...)             \
    do                                \
    {                                 \
        fprintf(stderr, __VA_ARGS__); \
    } while (0)
#define DPI_LOG_ERROR(...)            \
    do                                \
    {                                 \
        fprintf(stderr, __VA_ARGS__); \
    } while (0)

typedef enum dpi_protocol_tcp
{
    SSH,
    ProtocolTCPEnd
} dpi_protocol_tcp;

typedef enum dpi_protocol_udp
{
    NFTP,
    ProtocolUDPEnd
} dpi_protocol_udp;

// tcp连接的信息
typedef struct dpi_tcp_connection
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    dpi_protocol_tcp protocol;
} dpi_tcp_connection;

// 句柄定义
// 操作数据包的句柄
// 保存数据包中每个协议的报文数量
typedef struct dpi_result
{
    void *pcap_handle;                              // 存储pcap_t类型句柄
    unsigned int ether_count;                       // 以太网报文数量
    unsigned int ip_count;                          // ip报文数量
    unsigned int tcp_count;                         // tcp报文数量
    unsigned int udp_count;                         // udp报文数量
    unsigned int tcp_payload_count[ProtocolTCPEnd]; // TCP上层应用层对应协议的报文数
    unsigned int udp_payload_count[ProtocolUDPEnd]; // UDP上层应用层对应协议的报文数
    dpi_list *tcp_connection_list;                  // 存储tcp连接信息的链表
} dpi_result;

// 定义报文的解析信息
// 即每个协议报文长度，以及起始地址
typedef struct dpi_pkt
{
    uint32_t ether_len;                // 以太网报文长度
    struct ether_header *ether_packet; // 以太网报文的地址
    uint32_t ip_len;                   // ip报文长度
    struct iphdr *ip_packet;           // ip报文的地址
    union
    {
        struct
        {
            uint32_t tcp_len;          // tcp报文长度
            struct tcphdr *tcp_packet; // tcp报文的起始地址
        };
        struct
        {
            uint32_t udp_len;          // udp报文长度
            struct udphdr *udp_packet; // udp报文的起始地址
        };
    };
    uint32_t payload_len; // 数据区域的长度
    uint8_t *payload;     // 指向数据区域的指针
} dpi_pkt;

// 初始化
// pcapfile :要处理的pcap文件
// 返回值:设计一个句柄，这个句柄包含了结果
// 成功返回非空的指针，失败返回NULL
dpi_result *dpi_init(const char *pcapfile);

// 业务处理
// 自动执行报文解析
void dpi_loop(dpi_result *res);

// 释放资源
void dpi_destroy(dpi_result *res);

// 定义一个函数指针，用来识别TCP上层报文协议
typedef int (*dpi_protocol_analyze_func_t)(dpi_pkt *pkt);

// 声明函数指针数组，用来存储TCP上层报文协议的解析函数
extern dpi_protocol_analyze_func_t dpi_tcp_analyze_func[ProtocolTCPEnd];


// 声明函数指针数组，用来存储TCP上层报文协议的解析函数
extern dpi_protocol_analyze_func_t dpi_udp_analyze_func[ProtocolUDPEnd];