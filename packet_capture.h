#pragma once
#include <pcap/pcap.h>
#include <iostream>
#include <unistd.h>

const int snaplen = 65535;


// 数据包捕获类
// 对libpcap库的相关接口进行封装
class PacketCapture
{
    // 回调函数，负责处理数据包
    friend void process_packet(u_char* arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);

    public:
    PacketCapture(const char* device = nullptr);
    ~PacketCapture();
    
    void run();

    // 释放网络接口
    void close();


private:
    PacketCapture(const PacketCapture&) = delete;
    PacketCapture& operator = (const PacketCapture&) = delete;

    pcap_t* _handle;                     // 返回网络接口句柄
    char _errbuf[PCAP_ERRBUF_SIZE] {0};  // 存储出错信息
};
