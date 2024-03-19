#include <stdio.h>
#include <pcap/pcap.h>
#include "dpi.h"

void usage(const char *argv)
{
    fprintf(stderr, "usage :%s <pcap_file>\n", argv);
}

void display_result(dpi_result *res)
{
    printf("============================================================\n");
    printf("以太网报文数量: %u\n", res->ether_count);
    printf("ip报文数量: %u\n", res->ip_count);
    printf("tcp报文数量: %u\n", res->tcp_count);
    printf("udp报文数量: %u\n", res->udp_count);
    printf("ssh报文数量: %u\n", res->tcp_payload_count[SSH]);
    printf("============================================================\n");
    // 遍历tcp连接信息的链表，输出每个连接的信息
    dpi_list_node *node = res->tcp_connection_list->sentinal.next;
    while (node != &res->tcp_connection_list->sentinal)
    {
        dpi_tcp_connection *con = node->data;
        struct in_addr in;
        in.s_addr = con->src_ip;
        printf("src:%s:%d\t", inet_ntoa(in), ntohs(con->src_port));
        in.s_addr = con->dst_ip;
        printf("src:%s:%d\tprotocol:%d\n", inet_ntoa(in), ntohs(con->dst_port), con->protocol);
        node = node->next;
    }
    printf("============================================================\n");


}

int main(int argc, char **argv)
{
    // 如果main可执行文件后没有参数，就提示正确操作
    if (argc != 2)
    {
        usage(argv[0]);
        return -1;
    }

    // 初始化
    dpi_result *res = dpi_init(argv[1]);
    // 业务处理
    dpi_loop(res);
    display_result(res);
    // 资源释放
    dpi_destroy(res);
    // 测试
    return 0;
}
