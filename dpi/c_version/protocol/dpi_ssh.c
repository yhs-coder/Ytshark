#include "../dpi.h"
#include <string.h>
#include <stdio.h>
// ssh协议报文分析函数
int dpi_ssh_analyze(dpi_pkt *pkt)
{
    // 识别SSH报文的方法：（最简单）直接查看数据区开始的四个字节
    // 是否有"SSH-"标识
    if (pkt->payload_len <= 4)
    {
        // DPI_LOG_DEBUG("payload_len <= 4\n");
        return 0;
    }
    if (memcmp("SSH-", pkt->payload, 4) == 0)
    {
        return 1;
    }
    return 0;
}
