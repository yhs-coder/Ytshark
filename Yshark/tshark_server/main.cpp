#include "tshark_manager.h"
#include "loguru/loguru.hpp"

#include <thread>
#include <chrono>
#include <iomanip>
#include <sstream>
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
    time_t timestamp = 1741103714.153732000;
    std::tm* tm_local = std::localtime(&timestamp);
    std::ostringstream oss;
    oss << std::put_time(tm_local, "%Y-%m-%d %H:%M:%S ");
    std::string formatted_time = oss.str();
    std::cout << formatted_time << std::endl;
}

int main(int argc, char* argv[])
{
#if 0
    TsharkManager tshark_manager("D:/code/C++/Ytshark/Ytshark");
    tshark_manager.analysis_file("D:/code/C++/Ytshark/Ytshark/packet.pcap");
    //tshark_manager.analysis_file(R"(D:\code\C++\EasyTshark\packets.pcap)");
    tshark_manager.print_all_packets();
    /*for (size_t i = 1; i <= 500; i++) {
        std::vector<unsigned char> data;
        tshark_manager.get_packet_hex_data(i, data);
        for (auto byte : data) {
            printf("%02X ", byte);
        }
        printf("\n");
    }*/
//#else
    loguru::init(argc, argv);
    /*loguru::add_file("logs.txt", loguru::Append, loguru::Verbosity_MAX);
    LOG_F(INFO, "这是一个信息日志");
    LOG_F(WARNING, "这是一个警告日志");
    LOG_F(ERROR, "这是一个错误日志");*/

    std::thread t1(worker, 1);
    std::thread t2(worker, 2);
    t1.join();
    t2.join();

#endif
    test_time_stamp();
    std::cout << "Hello World!\n";
}

