#include "tshark_manager.h"
#include "loguru/loguru.hpp"

#include <thread>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <ctime>

#include <Windows.h>

#ifdef _WIN32
// windows系统，加载windows网络库
#pragma comment(lib, "ws2_32.lib")
#endif

void worker(int id) {
    LOG_F(INFO, "线程 %d 正在运行", id);
}


//std::string convert_timestamp_format() {
//
//}

void test_time_stamp() {
    // 获取微秒级时间戳
#if 0
    auto now_time_point = std::chrono::system_clock::now();
    auto micros = std::chrono::duration_cast<std::chrono::microseconds>(now_time_point.time_since_epoch());
    std::cout << "TimeStamp: " << micros.count() << "us " << std::endl;
#endif

#if 0
    auto now = std::chrono::system_clock::now();
    auto since_epoch = now.time_since_epoch();

    // 分离秒和毫秒
    std::chrono::seconds sec = std::chrono::duration_cast<std::chrono::seconds>(since_epoch);
    std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(since_epoch - sec);

    std::time_t t = sec.count(); //  返回自纪元以来的秒数（整数）。
    std::tm tm_buf;
    localtime_s(&tm_buf, &t);

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S") << '.' << std::setw(3) << std::setfill('0') << ms.count();
    std::cout << oss.str() << std::endl;
#endif

#if 0
    time_t timestamp = 1741103714.153732000;
    std::tm* tm_local = std::localtime(&timestamp);
    std::ostringstream oss;
    oss << std::put_time(tm_local, "%Y-%m-%d %H:%M:%S ");
    std::string formatted_time = oss.str();
    std::cout << formatted_time << std::endl;
#endif
#if 0
    double timestamp = 1741103714.153732000;
    int64_t sec = static_cast<int64_t>(timestamp);
    int64_t micro = static_cast<int64_t>((timestamp - sec) * 1e6);

    // 2. 转换为 time_point
    using namespace std::chrono;
    system_clock::time_point tp =
        system_clock::time_point(seconds(sec) + microseconds(micro));
    // 4. 转换为日历时间并格式化输出
    std::time_t t = system_clock::to_time_t(tp);
    auto tm = *std::localtime(&t);  // 转换为本地时区
    auto since_epoch = tp - system_clock::time_point();
    auto micro_part = std::chrono::duration_cast<microseconds>(since_epoch) % 1000000;

    // 输出结果
    std::cout << "原始时间戳: " << timestamp << "\n";
    std::cout << "处理后时间: "
        << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
        << "." << std::setw(6) << std::setfill('0') << micro_part.count()
        << std::endl;
#else
    double timestamp = 1741103714.153732000;
    // 将时间戳分解成秒数和微秒数
    std::time_t seconds = static_cast<std::time_t>(timestamp);
    std::cout << timestamp - seconds << std::endl;
    int microseconds = static_cast<int>((timestamp - seconds) * 1e6);

    // 转换成std::tm结构体
    std::tm local_time;
    localtime_s(&local_time, &seconds);
    std::ostringstream oss;
    oss << std::put_time(&local_time, "%Y-%m-%d %H:%M:%S") << '.' << std::setw(6) << std::setfill('0') << microseconds;
    std::cout << oss.str() << std::endl;
#endif
}

void loguru_test() {
    loguru::add_file("logs.txt", loguru::Append, loguru::Verbosity_MAX);
    LOG_F(INFO, "这是一个信息日志");
    LOG_F(WARNING, "这是一个警告日志");
    LOG_F(ERROR, "这是一个错误日志");

    std::thread t1(worker, 1);
    std::thread t2(worker, 2);
    t1.join();
    t2.join();
}

void print_network_adapters(TsharkManager& tm) {
    std::vector<AdapterInfo> adapters = tm.get_network_adapters();
    for (auto item : adapters) {
        LOG_F(INFO, "网卡[%d]: name[%s] remark[%s]", item.id, item.name.c_str(), item.remark.c_str());
    }
}

int main(int argc, char* argv[])
{
    // windwos控制台设置为utf-8编码
    SetConsoleOutputCP(CP_UTF8);
    /* std::cout << "h你好呀" << std::endl;
     std::wcout << L"你好呀" << std::endl;
     loguru::init(argc, argv);
     loguru::add_file("adapter_info.log", loguru::Append, loguru::Verbosity_MAX);
     LOG_F(INFO, "这是一个信息日志");*/
#if 1
    loguru::init(argc, argv);
    loguru::add_file("adapter_info.log", loguru::Append, loguru::Verbosity_MAX);
    TsharkManager tshark_manager(R"(D:\github_code\Ytshark\Yshark\tshark_server\tshark_server)");
    tshark_manager.analysis_file(R"(D:\github_code\Ytshark\Yshark\tshark_server\tshark_server\packet.pcap)");
    print_network_adapters(tshark_manager);
   /* std::vector<unsigned char> data;
    if (tshark_manager.get_packet_hex_data(501, data)) {
        for (auto byte : data) {
            printf("%02X ", byte);
        }
        printf("\n");
    }*/

    //tshark_manager.analysis_file(R"(D:\code\C++\EasyTshark\packets.pcap)");

    //tshark_manager.print_all_packets();

#endif
    //test_time_stamp();
    //loguru_test();
    return 0;
}

