#ifndef __TIME_STAMP_H__
#define __TIME_STAMP_H__
#include <stdio.h>
#include <pcap/pcap.h>
#include <time.h>
#include "exception.h"
#define MAX_BUFFER 255

struct TimeStamp
{
    // 时间戳 - 秒
    uint32_t ts_sec(const struct pcap_pkthdr *pkthdr) const noexcept
    {
        return pkthdr->ts.tv_sec;
    }
    // 时间戳 - 微秒
    uint32_t ts_usec(const struct pcap_pkthdr *pkthdr) const noexcept
    {
        return pkthdr->ts.tv_usec;
    }
    // 捕获数据包的长度
    uint32_t caplen(const struct pcap_pkthdr *pkthdr) const noexcept
    {
        return pkthdr->caplen;
    }
    uint32_t len(const struct pcap_pkthdr *pkthdr) const noexcept
    {
        return pkthdr->len;
    }

    // 处理并输出时间
    void show_time(const struct pcap_pkthdr *pkthdr) const
    {
        time_t time_stamp = ts_sec(pkthdr) + ts_usec(pkthdr) / 1000000;
        tm *tm = localtime(&time_stamp);
        char buf[MAX_BUFFER];
        if (tm)
        {
            // 将时间信息按照指定的格式转换成字符串
            strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
        }
        else
            throw IOException("strftime");
        printf("[%s.%d] caplen: %d ", buf, ts_usec(pkthdr), caplen(pkthdr));
    }
};

#endif