#include "dpi.h"
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>

//#include "dpi_pkt_main.c"

void dpi_pkt_ip(dpi_result* res, dpi_pkt* pkt); 

dpi_result* dpi_init(const char* pcapfile)
{
    // 1. 打开pcap文件
    char errbuf[PCAP_ERRBUF_SIZE] = {0};  // 错误信息errbuf
    pcap_t* handle = pcap_open_offline(pcapfile, errbuf); // 读取pcap文件
    if (!handle) {
        // 出错处理
        //fprintf(stderr, "Error in pacp_open_offline：%s\n",errbuf);
        DPI_LOG_DEBUG("Error in pacp_open_offline：%s\n",errbuf);
        return NULL;
    }
    dpi_result* res = (dpi_result*)malloc(sizeof(dpi_result));
    if (res == NULL) {
        //printf("Error in malloc\n");
        DPI_LOG_DEBUG("Error in malloc\n");
        return NULL;
    }
    memset(res, 0, sizeof(*res));
    // 将pcap打开文件产生的句柄存到res结构体中
    res->pcap_handle = handle;
    return res;
}

// 回调函数
void dpi_pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *data)
{
    // 每次解析一次报文，该函数就会被调用
    // static int count = 0;
    // count++;
    // printf("count : %d\n",count);
    dpi_result* res = (dpi_result*)user;
    // 以太网报文数量
    res->ether_count++;

    // 从packet header中输出每个报文的长度
    // caplen是实际捕获到的数据包长度
    // len是实际数据包的长度
    //printf("caplen:%d  len:%d\n", h->caplen, h->len);
    // 如果caplen！= len，说明数据包丢失，该报文可以丢弃掉
    if (h->caplen != h->len) {
        //printf("该报文数据包丢失...\n");
        DPI_LOG_DEBUG("该报文数据包丢失...\n");
        return;
    }

    // 解析以太网帧
    // 对于报文中已确定的字段，可以使用系统定义或者自动手搓的结构体来访问
    // 使用以太网帧的结构体，定义在 net/ethernet.h
    //struct ether_header* ethernet = (struct ether_header*)data;
    // 传过来的报文是网络字节序，需要转换成主机字节序
    //printf("type: %#X\n",ntohs(ethernet->ether_type));

    // 创建pkt结构体，标识解析路径
    dpi_pkt pkt;
    memset(&pkt, 0 , sizeof(pkt));
    pkt.ether_len = h->caplen;  // 记录以太网报文长度
    pkt.ether_packet = (struct ether_header*)data;  // 保存以太网报文起始地址

    // 解析ip报文
    pkt.ip_len = pkt.ether_len - sizeof(*pkt.ether_packet);
    pkt.ip_packet = (struct iphdr*)((char*)pkt.ether_packet + sizeof(*pkt.ether_packet));    // 计算ip报文的起始位置地址

    // 判断以太网帧之上是否为ip报文
    if (pkt.ether_packet->ether_type == htons(0x0800)) {
        // 调用解析ip报文的函数
        dpi_pkt_ip(res, &pkt);
    }
}    

void dpi_loop(dpi_result* res)
{
    // 2. 处理pcap文件
    pcap_loop((pcap_t*)res->pcap_handle, 0, dpi_pcap_callback, (u_char*)res);
    /* 等价于
        while (还有报文未处理) {
            dpi_pcap_callback(res, PacketHeader, PacketData);
        }
    */
}

void dpi_destroy(dpi_result* res)
{
    if (!res) {
        return;
    }
    // 释放pcap_t句柄
    pcap_close((pcap_t*)res->pcap_handle);
    // 释放动态空间
    free(res);
}
