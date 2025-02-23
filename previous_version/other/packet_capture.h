#pragma once
#include <pcap/pcap.h>
#include <stdio.h>
#include <unistd.h>

#include <iostream>
#include <map>

#include "arp_packet.h"
#include "dns_view.h"
#include "ethernetII.h"
#include "exception.h"
#include "http_message.h"
#include "ipv4_packet.h"
#include "rule_library.h"
// #include "sql_detector.h"
#include "tcp_packet.h"
#include "time_stamp.h"
#include "udp_packet.h"

const int snaplen = 65535;

// 数据包捕获类
// 对libpcap库的相关接口进行封装
class PacketCapture {
    // 回调函数，负责处理数据包
    friend void process_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);

public:
    PacketCapture(const char *handle = nullptr);
    ~PacketCapture();

    // 运行
    void run();

    // 释放网络接口
    void close();

    static std::map<AddrIPv4, std::string> arp_map;  // arp映射表
    static uint32_t _num;                            // 数据包编号
private:
    PacketCapture(const PacketCapture &) = delete;
    PacketCapture &operator=(const PacketCapture &) = delete;

    pcap_t *_handle;                    // 返回网络接口句柄
    char _errbuf[PCAP_ERRBUF_SIZE]{0};  // 存储出错信息
};
