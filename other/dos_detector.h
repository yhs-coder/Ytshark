#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <unordered_map>

#include "tcp_packet.h"

// dos攻击检测器接口
class AttackDetector {
public:
    virtual ~AttackDetector() = default;
    virtual void detect(const TcpPacket& packet, const std::string& ip) = 0;
};

// SYN FLOOD 攻击检测器
class SynFloodDetector : public AttackDetector {
public:
    void detect(const TcpPacket& packet, const std::string& ip) {
        clean();
        std::string src_ip;
        // ack有效
        if (packet.is_syn()) {
            _syn_counts[src_ip]++;
            if (_syn_counts[src_ip] > _syn_threshold)
                // todo: 此时发出邮件警告 send_alert
                std::cout << "SYN FLOOD" << std::endl;
        }
    }

private:
    // 清理过期计数
    void clean() {
        // 获取当前时间点
        auto now = std::chrono::system_clock::now();
        for (auto it = _syn_counts.begin(); it != _syn_counts.end(); it++) {
            if (now - std::chrono::system_clock::time_point{} > std::chrono::seconds(_time_window_sec))
                it = _syn_counts.erase(it);
        }
    }

    std::map<std::string, int> _syn_counts;  // 存储ip地址和syn包计数
    const int _syn_threshold = 1000;         // syn包阈值
    const int _time_window_sec = 60;         // 事件窗口，1分钟
};

// ACK Flood 攻击检测器
class AckFloodDetector : public AttackDetector {
public:
    void detect(const TcpPacket& packet, const std::string& ip) {
        clean();
        std::string src_ip = ip;
        // ack有效
        if (packet.is_syn()) {
            _ack_counts[src_ip]++;
            if (_ack_counts[src_ip] > _threshold)
                // todo: 此时发出邮件警告 send_alert
                std::cout << "ACK FLOOD" << std::endl;
        }
    }

private:
    // 清理过期计数
    void clean() {
        // 获取当前时间点
        auto now = std::chrono::system_clock::now();
        for (auto it = _ack_counts.begin(); it != _ack_counts.end(); it++) {
            if (now - std::chrono::system_clock::time_point{} > std::chrono::seconds(_time_window_sec))
                it = _ack_counts.erase(it);
        }
    }

    const int _threshold = 100;              // ack阈值
    std::map<std::string, int> _ack_counts;  // 存储ip地址和ack包计数
    const int _time_window_sec = 60;         // 事件窗口，1分钟
};

// Port Scan 攻击检测器
class PortScanDetector : public AttackDetector {
public:
    // 进行端口扫描检测
    void detect(const TcpPacket& packet, const std::string& ip) {
        clean();
        std::string src_ip = ip;
        int dst_port = packet.target_port();
        _port_scan_info[src_ip].insert(dst_port);
        if (_port_scan_info[src_ip].size() > _port_threshold) {
            // todo: send_alert 发送邮件告警
            std::cout << "Port Scan" << std::endl;
            _port_scan_info[src_ip].clear();
        }
    }

private:
    // 清理过期的端口记录
    void clean() {
        auto now = std::chrono::system_clock::now();
        for (auto it = _port_scan_info.begin(); it != _port_scan_info.end(); it++) {
            bool expired = true;
            // 检查每个端口
            for (auto& port : it->second) {
                if (now - std::chrono::system_clock::time_point{} > std::chrono::seconds(_time_window_sec)) {
                    expired = false;
                    break;
                }
            }
            if (expired)
                it = _port_scan_info.erase(it);
        }
    }

    std::map<std::string, std::set<int>> _port_scan_info;  // 存储ip地址和尝试连接的端口集合
    const int _port_threshold = 100;                       // 端口阈值
    const int _time_window_sec = 60;                       // 事件窗口，1分钟
};

//  DosAttackDetector类现负责管理所有攻击检测器
class DosAttackDetector {
public:
    DosAttackDetector()
        : _syn_flood_detector(std::make_unique<SynFloodDetector>()), _ack_flood_detector(std::make_unique<SynFloodDetector>()), _port_scan_detector(std::make_unique<SynFloodDetector>()) {}

    void detect(const TcpPacket& packet, const std::string& ip) {
        // 检测syn泛洪攻击
        _syn_flood_detector->detect(packet, ip);
        _ack_flood_detector->detect(packet, ip);
        _port_scan_detector->detect(packet, ip);
    }

private:
    std::unique_ptr<AttackDetector> _syn_flood_detector;
    std::unique_ptr<AttackDetector> _ack_flood_detector;
    std::unique_ptr<AttackDetector> _port_scan_detector;
};
