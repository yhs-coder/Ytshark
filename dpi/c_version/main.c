#include <stdio.h>
#include <pcap/pcap.h>
#include "dpi.h"

void usage(const char* argv) 
{
    fprintf(stderr, "usage :%s <pcap_file>\n",argv);
}

void display_result(dpi_result* res)
{
    printf("error_count: %u\n",res->error_count);
    printf("================================================\n");
    printf("以太网报文数量: %u\n",res->ether_count);
    printf("ip报文数量: %u\n",res->ip_count);
    printf("tcp报文数量: %u\n",res->tcp_count);
    printf("udp报文数量: %u\n",res->udp_count);
    printf("ssh报文数量: %u\n",res->ssh_count);
}


int main(int argc, char** argv)
{
    // 如果main可执行文件后没有参数，就提示正确操作
    if (argc != 2) {
        usage(argv[0]);
        return -1;
    }

    // 初始化
    dpi_result* res = dpi_init(argv[1]);
    // 业务处理
    dpi_loop(res);
    display_result(res);
    // 资源释放
    dpi_destroy(res);
    // 测试
    return 0;
}

