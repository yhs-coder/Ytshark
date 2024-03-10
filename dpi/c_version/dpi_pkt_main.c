#include "dpi.h"
#include <stdio.h>
#include <unistd.h>
// 解析ip报文

void dpi_pkt_tcp(dpi_result* res, dpi_pkt* pkt); 
void dpi_pkt_udp(dpi_result* res, dpi_pkt* pkt);

void dpi_pkt_ip(dpi_result* res, dpi_pkt* pkt) 
{
    // ip报文计数
    res->ip_count++;

    // 处理IPV4版本
    if (pkt->ip_packet->version != 4)
    {
        printf("IP version is not 4\n");
        return;
    }
    int ip_header_len = pkt->ip_packet->ihl << 2;   // 首部长度单位是4字节,  << 2相当于*4
    int ip_total_len = ntohs(pkt->ip_packet->tot_len);
    
    // 只处理片片移为0
    if ((ntohs(pkt->ip_packet->frag_off)& 0x1fff) != 0) 
    {
        printf("IP frag off not eq 0\n");
        return;
    }
    switch(pkt->ip_packet->protocol)
    {
        case 6:
            // TCP
            // 计算tcp报文数据的长度和起始位置
            pkt->tcp_len = ip_total_len - ip_header_len;
            // 如果数据区没有数据，跳过
            if (pkt->tcp_len <= 0)
                return;
            pkt->tcp_packet = (char*)pkt->ip_packet + ip_header_len;
            dpi_pkt_tcp(res,pkt);
            break;
        case 17:
            // UDP
            dpi_pkt_udp(res,pkt);
            break;
        default:
            break;
    }
}

void dpi_pkt_tcp(dpi_result* res, dpi_pkt* pkt)
{
    
}
void dpi_pkt_udp(dpi_result* res, dpi_pkt* pkt)
{

}
