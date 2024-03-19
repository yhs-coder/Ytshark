#include "dpi.h"
#include <stdio.h>
#include <unistd.h>

// 声明ssh解析函数
int dpi_ssh_analyze(dpi_pkt *pkt);

// 初始化函数指针数组
dpi_protocol_analyze_func_t dpi_tcp_analyze_funcs[ProtocolTCPEnd] =
    {
        dpi_ssh_analyze};

// 解析ip报文
void dpi_pkt_tcp(dpi_result *res, dpi_pkt *pkt);
void dpi_pkt_udp(dpi_result *res, dpi_pkt *pkt);

void dpi_pkt_ip(dpi_result *res, dpi_pkt *pkt)
{
    // ip报文计数
    res->ip_count++;

    // 处理IPV4版本
    if (pkt->ip_packet->version != 4)
    {
        // fprintf(stderr,"IP version is not 4\n");
        DPI_LOG_DEBUG("IP version is not 4\n");
        return;
    }
    int ip_header_len = pkt->ip_packet->ihl << 2; // 首部长度单位是4字节,  << 2相当于*4
    int ip_total_len = ntohs(pkt->ip_packet->tot_len);

    // 判断片偏移是否为0
    if ((ntohs(pkt->ip_packet->frag_off) & 0x1fff) != 0)
    {
        // fprintf(stderr,"IP frag off not eq 0\n");
        DPI_LOG_DEBUG("IP frag off not eq 0\n");
        return;
    }

    // 判断ip协议上层的协议
    switch (pkt->ip_packet->protocol)
    {
    case 6:
        // TCP
        // 计算tcp报文数据的长度和起始位置
        pkt->tcp_len = ip_total_len - ip_header_len;
        // 如果数据区没有数据，跳过
        if (pkt->tcp_len <= 0)
            return;
        pkt->tcp_packet = (struct tcphdr *)((char *)pkt->ip_packet + ip_header_len);
        dpi_pkt_tcp(res, pkt);
        break;
    case 17:
        // UDP
        // 计算udp报文数据的长度和起始位置
        pkt->udp_len = ip_total_len - ip_header_len;
        // 如果数据区没有数据，跳过
        if (pkt->udp_len <= 0)
            return;
        pkt->udp_packet = (char *)pkt->ip_packet + ip_header_len;
        dpi_pkt_udp(res, pkt);
        break;
    default:
        break;
    }
}

// 解析tcp报文
void dpi_pkt_tcp(dpi_result *res, dpi_pkt *pkt)
{
    res->tcp_count++;
    // 计算tcp首部长度
    int tcp_header_len = pkt->tcp_packet->doff << 2; // 首部长度单位是4字节，使用 << 2 === *4
    // 计算数据区域的长度
    pkt->payload_len = pkt->tcp_len - tcp_header_len; // 数据区域的长度 = tcp报文长度 - tcp首部长度
    pkt->payload = (uint8_t *)pkt->tcp_packet + tcp_header_len;

    // 看看以下报文是不是已经被标识的连接
    // 是的话：对应的协议报文的数量++
    dpi_list_node *node = res->tcp_connection_list->sentinal.next;
    while (node != &res->tcp_connection_list->sentinal)
    {
        dpi_tcp_connection *cur = (dpi_tcp_connection *)node->data;
        // 判断已经识别的连接跟当前的报文是否为同一连接
        // 比较源ip和目标ip,以及源端口和目的端口
        if (cur->src_ip == pkt->ip_packet->saddr && cur->dst_ip == pkt->ip_packet->daddr && cur->src_port == pkt->tcp_packet->source && cur->dst_port == pkt->tcp_packet->dest)
        {
            // 报文匹配了已有的连接，该协议报文数++
            res->tcp_payload_count[cur->protocol]++;
            return;
        }

        // 连接的反方向判定
        if (cur->src_ip == pkt->ip_packet->daddr && cur->dst_ip == pkt->ip_packet->saddr && cur->src_port == pkt->tcp_packet->dest && cur->dst_port == pkt->tcp_packet->source)
        {
            // 报文匹配了已有的连接，该协议报文数++
            res->tcp_payload_count[cur->protocol]++;
            return;
        }

        node = node->next;
    }

    // 否的话：继续遍历每一个协议，识别该报文是什么协议
    int i = 0;
    for (; i < ProtocolTCPEnd; i++)
    {
        if (dpi_tcp_analyze_funcs[i](pkt))
        {
            // 匹配对应的协议
            res->tcp_payload_count[i]++;

            // 标记一下是什么协议
            // 创建一个存储连接的结构体
            dpi_tcp_connection *con = (dpi_tcp_connection *)malloc(sizeof(dpi_tcp_connection));
            if (con == NULL)
            {
                printf("malloc error\n");
                break;
            }
            // 记录当前报文的连接信息，即源/目的的ip和端口
            con->src_ip = pkt->ip_packet->saddr;
            con->dst_ip = pkt->ip_packet->daddr;
            con->src_port = pkt->tcp_packet->source;
            con->dst_port = pkt->tcp_packet->dest;
            con->protocol = i;
            // 将连接的信息插入链表
            dpi_list_append(res->tcp_connection_list, con);
            break;
        }
    }
}

// 解析udp报文
void dpi_pkt_udp(dpi_result *res, dpi_pkt *pkt)
{
    res->udp_count++;
}
