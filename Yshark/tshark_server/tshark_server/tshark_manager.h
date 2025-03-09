#ifndef TSHARKMANAGER_H
#define TSHARKMANAGER_H
#include "tshark_datatype.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "ip2region_util.h"
#include "loguru/loguru.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <map>
#include <iomanip>
#include <ctime>
#include <chrono>
#include <set>
#include <regex>
#include <thread>


class TsharkManager
{
public:
    TsharkManager(std::string work_dir);
    ~TsharkManager();

    // 分析数据包文件
    bool analysis_file(std::string file_path);

    // 打印所有数据包的信息
    void print_all_packets();

    // 获取指定编号数据包的十六进制数据
    bool get_packet_hex_data(uint32_t frame_number, std::vector<unsigned char>& data);

    // 转换时间戳格式
    std::string convert_timestamp_format(std::string timestamp);

    // 枚举网卡列表
    std::vector<AdapterInfo> get_network_adapters();

    // 开始抓包
    bool start_capture(std::string adapter_name);

    // 停止抓包
    bool stop_capture();

    // 设置fd为非阻塞
    void set_non_blocking(int fd);
private:
    // 解析每一行
    bool parse_line(std::string line, std::shared_ptr<Packet> packet);

    // 在线采集数据包的工作线程
    void capture_work_thread_entry(std::string adapter_name);

private:
    // tshark运行路径
    std::string _tshark_path;

    // 当前分析的文件路径
    std::string _current_file_path;
    
    // 是否停止抓包的标记
    bool _stop_flag;

    // 在线抓包的tshark进程PID
    //PID_T _capture_thsark_pid = 0;

    // 分析得到的所有数据包信息，key时数据包ID, value是数据包信息指针，方便根据编号获取指定数据包信息
    //std::unordered_map<uint32_t, std::shared_ptr<Packet>> _all_packets;
    std::map<uint32_t, std::shared_ptr<Packet>> _all_packets;

    // 在线分析线程
    std::shared_ptr<std::thread> _capture_work_thread;
};

#endif