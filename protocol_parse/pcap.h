#ifndef __PCAP_H__
#define __PCAP_H__

#include <vector>
#include <time.h>
#include "base.h"
#include "map_file.h"



#define PCAP_MAGIC_MODE                 0xA1B2C3D4
#define PCAP_MAGIC_OPPOSITE_MODE        0xD4C3B2A1
#define IS_PCAP_MAGIC_VALUE(magic)      ((magic) == PCAP_MAGIC_MODE || (magic) == PCAP_MAGIC_OPPOSITE_MODE)

// 解析pcap文件错误码
#define PCAP_PARSE_SUCCESS              0       // 解析pcap文件完成       
#define PCAP_PARSE_ERROR_LOAD_FILE      -1      // 加载pcap文件出错
#define PCAP_PARSE_ERROR_HEADER         -11     // 获取文件内容出错
#define PCAP_PARSE_ERROR_MAGIC          -12     // 获取文件内容头出错
#define PCAP_PARSE_ERROR_PACKET_HEADER  -21     // 获取pcap数据包头内容出错
#define PCAP_PARSE_ERROR_PACKET_DATA    -22     // 获取pcap数据包内容出错

#define PCAP_HEADER_BYTES               24      // pcap文件头长度为24字节
#define PCAP_PACKET_HEADER_BYTES        16      // 数据包头长度为16字节

// pcap文件头
struct PcapHeader
{
    uint32_t magic;                 // 大小端标识
    uint16_t major;                 // 主要版本号
    uint16_t minor;                 // 次要版本号
    uint32_t this_zone;             // 当地标准时间
    uint32_t sig_flags;             // 时间戳精度
    uint32_t snap_len;              // 数据包最大存储长度
    uint32_t link_type;             // 链路类型

    void pcap_header_info();        // 显示pcap文件头的信息
    void opposite_byte_order();     // 将字节顺序进行反转
};

// pcap数据包头
struct PacketHeader
{
    uint32_t timestamp_s;           // 捕获数据包时间戳高位，秒
    uint32_t timestamp_ms;          // 捕获数据包时间戳低位，毫秒
    uint32_t caplen;                // 捕获数据包的长度
    uint32_t len;                   // 实际数据包（帧）的长度

    void pcap_packet_header_info(); //显示数据包头的信息
    void opposite_byte_order();     // 将字节顺序进行反转
};

// 数据包头和数据包数据 封装
struct PcapPacket
{
    PacketHeader header;
    void *packet_data;
};

// pcap文件
class PcapFile
{
public:
    PcapHeader _file_header;                // pcap文件头
    std::vector<PcapPacket> _packets;       // 将数据包内容存储在数组中 （包括数据包头）
    MapFile _map_file;                      // 映射文件

    PcapFile();
    ~PcapFile();
    //void *fun_get_value(uint32_t value);    
    bool is_load_file();                    // 是否加载了文件
    int load_file(const char *file_path);   // 加载文件
    int parse();                            // 解析pcap文件

};

#endif
