#pragma once
#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <regex>
#include <set>
#include <string>
#include <unordered_map>

#include "mail.h"
#include "tcp_packet.h"

struct AlertMail {
    AlertMail()
        : from("15360969181@163.com"), password("YIQGLSLBJEISXEHS"), to("yhs_mail@126.com"), subject("安全库检测异常！") {
        message = "";
    }
    std::string from;      // 发送者邮箱
    std::string password;  // 授权码
    std::string to;        // 接收者邮箱
    std::string subject;   // 邮件标题
    std::string message;   // 邮件内容
};

// 攻击检测器接口
class AttackDetector {
public:
    virtual ~AttackDetector() = default;
    virtual void detect(const TcpPacket& packet, const std::string& ip) = 0;
    virtual bool detect(const std::string& data) = 0;
    virtual void send_alert() = 0;
    std::unique_ptr<SmtpBase> _base;
};

// SQL注入攻击检测器
class SqlInjectionDetector : public AttackDetector {
private:
    std::regex _pattern;
    // std::unique_ptr<SmtpBase> _base;

public:
    SqlInjectionDetector()
        : _pattern(
              "(?:\\bUNION\\b|\\bSELECT\\b|\\bWHERE\\b|\\bORDER BY\\b|\\bAND\\b|\\bOR\\b)|"
              "(?:\\%7C%7C|\\%26%26|\\%23|\\%2D%2D|\\%2D\\+\\+)|"
              "(--|#|--+|#+)|"  // 注释符号
              "(?:\\bUPDATEXML\\(|\\bEXTRACT\\(|\\bCONCAT\\(|\\bGROUP_CONCAT\\()|"
              "(\\bIF\\(|\\bDATABASE\\(|\\bUSER\\(|\\bSYSTEM_USER\\))",
              std::regex_constants::icase) {}
    void detect(const TcpPacket& packet, const std::string& ip) override {
    }
    bool detect(const std::string& data) {
        if (std::regex_search(data, _pattern)) {
            send_alert();
        }
    }
    void send_alert() {
        AlertMail test_mail;
        test_mail.message = "hacking!!!!服务器遭受sql攻击！！！请尽快处理！！！";
        _base = std::make_unique<SslSmtpEmail>("smtp.163.com", "465");
        _base->send_email(test_mail.from, test_mail.password, test_mail.to, test_mail.subject, test_mail.message);
        sleep(10);
        exit(-1);
    }
};

class XSSInjectionDetector : public AttackDetector {
private:
    std::regex _pattern;

public:
    XSSInjectionDetector()
        : _pattern(
              // 检测<script>标签,包括url编码 "(?:<script[^>]*>.*?</script>)|"
              "(?:(%3C|<)script(%3E|>).*(%3C|<)(%2F|/)(script)(%3E|>))|"
              // 检测内联事件处理器，如 onclick、onerror 等
              "(?:<[^>]*(\\s*(on[a-z]+=(\"[^\"]*\"|'[^']*'|[^'\">\\s]+)))+>)|"
              // 检测url编码的内联事件处理器
              "(?:%3C[^%3E]*(%20*(on[a-z]+=(%22[^%22]*%22|%27[^%27]*%27|[^%27%22%3E%20]+)))+%20*%3E)|"
              // 检测伪协议，javascript伪协议: data伪协议:
              "(?:(javascript|data)[:\"'][^:<>\"']*)|"
              // 检测url编码的伪协议
              "(?:(javascript|data):[^:<>%22%27]*)"
              // 检测base64编码的数据URI
              "(?:base64,\\s*[a-zA-Z0-9+/]+(=|==)*)|"
              // 检测HTML实体，检测编码绕过情况
              "(?:&#[xXu]?[0-9a-fA-F]+;)|",
              // 检测混合大小写的javascript
              std::regex_constants::icase | std::regex_constants::ECMAScript) {}
    void detect(const TcpPacket& packet, const std::string& ip) override {
    }

    bool detect(const std::string& data) {
        if (std::regex_search(data, _pattern)) {
            send_alert();
        }
    }
    void send_alert() {
        AlertMail test_mail;
        test_mail.message = "hacking!!!!服务器遭受xss攻击！！！";
        _base = std::make_unique<SslSmtpEmail>("smtp.163.com", "465");
        _base->send_email(test_mail.from, test_mail.password, test_mail.to, test_mail.subject, test_mail.message);
    }
};

// SYN Flood攻击检测器
class SynFloodDetector : public AttackDetector {
public:
    void detect(const TcpPacket& packet, const std::string& ip) override {
        clean();
        std::string src_ip;
        // ack有效
        if (packet.is_syn()) {
            _syn_counts[src_ip]++;
            if (_syn_counts[src_ip] > _syn_threshold) {
                // todo: 此时发出邮件警告 send_alert
                std::cout << "SYN FLOOD" << std::endl;
                send_alert();
            }
        }
    }
    bool detect(const std::string& data) {
    }

    void send_alert() {
        AlertMail test_mail;
        test_mail.message = "hacking!!!!服务器遭受SYN FLOOD攻击！！！请尽快处理！！！";
        _base = std::make_unique<SslSmtpEmail>("smtp.163.com", "465");
        _base->send_email(test_mail.from, test_mail.password, test_mail.to, test_mail.subject, test_mail.message);
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
// ACK Flood攻击检测器
class AckFloodDetector : public AttackDetector {
public:
    void detect(const TcpPacket& packet, const std::string& ip) override {
        clean();
        std::string src_ip = ip;
        // ack有效
        if (packet.is_syn()) {
            _ack_counts[src_ip]++;
            if (_ack_counts[src_ip] > _threshold) {
                // todo: 此时发出邮件警告 send_alert
                std::cout << "ACK FLOOD" << std::endl;
                send_alert();
            }
        }
    }
    bool detect(const std::string& data) {
    }
    void send_alert() {
        AlertMail test_mail;
        test_mail.message = "hacking!!!!服务器遭受ACK FLOOD攻击！！！请尽快处理！！！";
        _base = std::make_unique<SslSmtpEmail>("smtp.163.com", "465");
        _base->send_email(test_mail.from, test_mail.password, test_mail.to, test_mail.subject, test_mail.message);
    }

private:
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

// Port Scan攻击检测器
class PortScanDetector : public AttackDetector {
public:
    void detect(const TcpPacket& packet, const std::string& ip) override {
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
    bool detect(const std::string& data) {
    }

    void send_alert() {
        AlertMail test_mail;
        test_mail.message = "hacking!!!!服务器遭受端口扫描攻击！！！请尽快处理！！！";
        _base = std::make_unique<SslSmtpEmail>("smtp.163.com", "465");
        _base->send_email(test_mail.from, test_mail.password, test_mail.to, test_mail.subject, test_mail.message);
    }

private:
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
    const int _time_window_sec = 60;
};

// 攻击检测器工厂类
class AttackDetectorFactory {
public:
    static std::unique_ptr<AttackDetector> create_detector(const std::string& type) {
        if (type == "sql") {
            return std::make_unique<SqlInjectionDetector>();
        } else if (type == "xss") {
            return std::make_unique<XSSInjectionDetector>();
        } else if (type == "syn flood") {
            return std::make_unique<SynFloodDetector>();
        } else if (type == "ack flood") {
            return std::make_unique<AckFloodDetector>();
        } else if (type == "portscan") {
            return std::make_unique<PortScanDetector>();
        }
        return nullptr;
    }
};

class RuleLibrary {
private:
    std::map<std::string, std::unique_ptr<AttackDetector>> _detectors;

public:
    // 创建对象自动加载安全检测器
    RuleLibrary() {
        register_detector("sql", "sql");
        register_detector("xss", "xss");
        register_detector("syn flood", "syn flood");
        register_detector("ack flood", "ack flood");
        register_detector("portscan", "portscan");
    }
    void register_detector(const std::string& name, const std::string& type) {
        auto detector = AttackDetectorFactory::create_detector(type);
        if (detector) {
            _detectors[name] = std::move(detector);
        }
    }

    void detect_all(const TcpPacket& packet, const std::string& ip) {
        for (auto& pair : _detectors) {
            pair.second->detect(packet, ip);
        }
    }

    void detect_all(const std::string& data) {
        for (auto& pair : _detectors) {
            pair.second->detect(data);
        }
    }
};