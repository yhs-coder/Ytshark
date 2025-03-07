#include "tshark_manager.h"
#include "utf8_to_ansi.h"

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
// 使用宏使用windows和unix的不同popen实现
#define popen _popen
#define pclose _pclose
#define localtime_r(time, result) localtime_s(result, time)
#else
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <cstdio>
#endif


TsharkManager::TsharkManager(std::string work_dir)
{
    _tshark_path = "D:/setup/Wireshark/tshark";
    std::string xdb_path = work_dir + "/third_library/ip2region/ip2region.xdb";
    IP2RegionUtil::init(xdb_path);
}

TsharkManager::~TsharkManager()
{
}

bool TsharkManager::analysis_file(std::string file_path)
{
    std::vector<std::string> tshark_args = {
        _tshark_path,
        "-r", file_path,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "frame.cap_len",
        "-e", "eth.src",
        "-e", "eth.dst",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "tcp.srcport",
        "-e", "udp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
    };

    // 拼接tshark命令
    std::string command;
    for (auto arg : tshark_args) {
        command += arg;
        command += " ";
    }

    // 创建管道，执行thsark命令
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        //std::cerr << "Failed to run tshark command!" << std::endl;
        LOG_F(ERROR, "Failed to run tshark command!");
        return false;
    }


    // 从管道读取数据，处理当前报文在文件中的偏移量
    char buffer[4096]{};
    // 偏移pcap全局文件头24字节
    uint32_t file_offset = sizeof(PcapHeader);
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::shared_ptr<Packet> packet = std::make_shared<Packet>();
        if (!parse_line(buffer, packet)) {
            LOG_F(ERROR, buffer);
            return false;
        }

        // 计算当前报文的的偏移量, 然后记录在packet中
        packet->file_offset = file_offset + sizeof(PacketHeader);
        // 更新偏移游标
        file_offset = file_offset + sizeof(PacketHeader) + packet->cap_len;

        // 获取地理位置
        packet->src_location = IP2RegionUtil::get_ip_location(packet->src_ip);
        packet->dst_location = IP2RegionUtil::get_ip_location(packet->dst_ip);

        // 将分析后的数据包插入保存起来
        _all_packets.insert(std::make_pair(packet->frame_number, packet));
    }

    // 关闭管道
    pclose(pipe);

    // 记录当前分析的文件路径
    _current_file_path = file_path;
    LOG_F(INFO, "分析完成，数据包总数：%zu", _all_packets.size());
    std::cout << "分析完成" << std::endl;
    return true;
}

void TsharkManager::print_all_packets()
{
    for (auto pair : _all_packets) {
        std::shared_ptr<Packet> packet = pair.second;
        // 构建JSON对象
        rapidjson::Document pkt_obj;
        rapidjson::Document::AllocatorType& allocator = pkt_obj.GetAllocator();

        // 设置JSON为Object对象类型
        pkt_obj.SetObject();

        // 添加JSON字段
        pkt_obj.AddMember("frame_number", packet->frame_number, allocator);
        pkt_obj.AddMember("timestamp", rapidjson::Value(packet->time.c_str(), allocator), allocator);
        pkt_obj.AddMember("src_mac", rapidjson::Value(packet->src_mac.c_str(), allocator), allocator);
        pkt_obj.AddMember("dst_mac", rapidjson::Value(packet->dst_mac.c_str(), allocator), allocator);
        pkt_obj.AddMember("src_ip", rapidjson::Value(packet->src_ip.c_str(), allocator), allocator);
        pkt_obj.AddMember("src_location", rapidjson::Value(packet->src_location.c_str(), allocator), allocator);
        pkt_obj.AddMember("src_port", packet->src_port, allocator);
        pkt_obj.AddMember("dst_ip", rapidjson::Value(packet->dst_ip.c_str(), allocator), allocator);
        pkt_obj.AddMember("dst_location", rapidjson::Value(packet->dst_location.c_str(), allocator), allocator);
        pkt_obj.AddMember("dst_port", packet->dst_port, allocator);
        pkt_obj.AddMember("protocol", rapidjson::Value(packet->protocol.c_str(), allocator), allocator);
        pkt_obj.AddMember("info", rapidjson::Value(packet->info.c_str(), allocator), allocator);
        pkt_obj.AddMember("file_offset", packet->file_offset, allocator);
        pkt_obj.AddMember("cap_len", packet->cap_len, allocator);
        pkt_obj.AddMember("len", packet->len, allocator);

        // 序列化为 JSON 字符串
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        pkt_obj.Accept(writer);

        // 打印JSON输出
        std::cout << buffer.GetString() << std::endl;
    }
}

bool TsharkManager::get_packet_hex_data(uint32_t frame_number, std::vector<unsigned char>& data)
{
    // 检查编号有效性
    if (_all_packets.find(frame_number) == _all_packets.end()) {
        LOG_F(ERROR, "找不到编号为 %d 的数据包", frame_number);
        return false;
    }
    // 获取指定编号数据包的信息
    std::shared_ptr<Packet> packet_data = _all_packets[frame_number];

    // 打开文件
    std::ifstream file(_current_file_path, std::ios::binary);
    if (!file) {
        //std::cerr << "Failed to open file." << std::endl;
        LOG_F(ERROR, "无法打开文件：%s", _current_file_path);
        return false;
    }
    // 每次重置到pcap文件起始位置，移动数据包对应的偏移量到报文数据位置
    file.seekg(packet_data->file_offset, std::iostream::beg);
    if (!file.good()) {
        LOG_F(ERROR, "无法定位到指定偏移量：%u.", packet_data->file_offset);
    }
    // 确保读取数据时，缓冲区大小足够
    data.resize(packet_data->cap_len);
    file.read(reinterpret_cast<char*>(data.data()), packet_data->cap_len);
    // 验证实际读取的字节数
    const std::streamsize bytes_read = file.gcount();
    if (bytes_read != packet_data->cap_len) {
        LOG_F(ERROR, "读取字节数错误（预期 %u，实际 %lld）", packet_data->cap_len, bytes_read);
        data.resize(0);  // 清空无效数据
        return false;
    }
    return true;
}

std::string TsharkManager::convert_timestamp_format(std::string timestamp)
{
    // 将时间戳分解成秒数和微秒数
    size_t dot_pos = timestamp.find('.');
    int64_t seconds = static_cast<std::int64_t>(std::stod(timestamp.substr(0, dot_pos)));
    std::string mirco_str = timestamp.substr(dot_pos + 1);
    // 字符串截取微妙6位数
    int64_t microseconds = static_cast<int64_t>(std::stod(mirco_str.substr(0, 6)));

    // 转换成std::tm结构体
    std::tm local_time;
    localtime_r(&seconds, &local_time);

    // 时间格式化

#if 1
    std::ostringstream oss;
    oss << std::put_time(&local_time, "%Y-%m-%d %H:%M:%S") << '.' << std::setw(6) << std::setfill('0') << microseconds;
    return oss.str();
#else
    char datetime[128]{};
    strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", &local_time);
    char result[256]{};
    // 字符串拼接
    snprintf(result, sizeof(result), "%s.%06d", datetime, microseconds);
    return std::string(result);
#endif
}

std::vector<AdapterInfo> TsharkManager::get_network_adapters()
{
    // 需要过滤掉的虚拟网卡
    std::set<std::string> special_interfaces = { "VMware Network Adapter VMnet8", "VMware Network Adapter VMnet1" };
    std::vector<AdapterInfo> interfaces;
    char buffer[256] = { 0 };
    std::string result;

    // 启动tshark -D 命令
    std::string cmd = _tshark_path + " -D";
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("Failed to run tshark command.");
    }

    // 读取tshark输出
    while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr) {
        result += buffer;
    }

    // 编码转换
    //UTF8TOANSIString(result);
    // 解析tshark的输出，输出格式为：
    // 1. \Device\NPF_{xxxxxx} (网卡描述)
    std::istringstream stream(result);
    std::string line;
    int index = 1;
    while (std::getline(stream, line)) {
        // 查找第一个空格S
        size_t start_pos = line.find(' ');
        if (start_pos != std::string::npos) {
            // 查找第二个空格
            size_t end_pos = line.find(' ', start_pos + 1);
            std::string interface_name;
            if (end_pos != std::string::npos) {
                // 提取中间的网卡名称
                interface_name = line.substr(start_pos + 1, end_pos - start_pos - 1);
            }
            else {
                // 没有网卡描述名称，提取编号后网卡名称
                interface_name = line.substr(start_pos + 1);
            }

            // 过滤掉特殊网卡
            if (special_interfaces.find(interface_name) != special_interfaces.end()) {
                continue;
            }

            AdapterInfo adapter_info;
            adapter_info.name = interface_name;
            adapter_info.id = index++;
            // 处理最后的网卡描述名称
            if (line.find("(") != std::string::npos && line.find(")") != std::string::npos) {
                size_t first = line.find("(");
                size_t end = line.find(")") - first - 1;
                adapter_info.remark = line.substr(first + 1, end);
            }
            interfaces.push_back(adapter_info);

        }
    }

    return interfaces;
}

bool TsharkManager::parse_line(std::string line, std::shared_ptr<Packet> packet)
{
    // 编码转换
    //UTF8TOANSIString(line);
    if (line.back() == '\n') {
        line.pop_back();
    }

    std::vector<std::string> fields;

    size_t start = 0, end;
    // 实现字符串拆分
    while ((end = line.find('\t', start)) != std::string::npos) {
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    // 添加最后一个子串
    fields.push_back(line.substr(start));

    // 字段顺序：
    // 0: frame.number
    // 1: frame.time_epoch
    // 2: frame.len
    // 3: frame.cap_len
    // 4: eth.src
    // 5: eth.dst
    // 6: ip.src
    // 7: ipv6.src
    // 8: ip.dst
    // 9: ipv6.dst
    // 10: tcp.srcport
    // 11: udp.srcport
    // 12: tcp.dstport
    // 13: udp.dstport
    // 14: _ws.col.Protocol
    // 15: _ws.col.Info



    if (fields.size() >= 16) {
        packet->frame_number = std::stoi(fields[0]);
        // 转换时间戳格式
        packet->time = convert_timestamp_format(fields[1]);
        packet->len = std::stoi(fields[2]);
        packet->cap_len = std::stoi(fields[3]);
        packet->src_mac = fields[4];
        packet->dst_mac = fields[5];
        packet->src_ip = fields[6].empty() ? fields[7] : fields[6];
        packet->dst_ip = fields[8].empty() ? fields[9] : fields[8];
        if (!fields[10].empty() || !fields[11].empty()) {
            packet->src_port = std::stoi(fields[10].empty() ? fields[11] : fields[10]);
        }
        if (!fields[12].empty() || !fields[13].empty()) {
            packet->dst_port = std::stoi(fields[12].empty() ? fields[13] : fields[12]);
        }
        packet->protocol = fields[14];
        packet->info = fields[15];
        return true;
    }
    else {
        return false;
    }
}

