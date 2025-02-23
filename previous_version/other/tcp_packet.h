#ifndef __TCP_PACKET_H__
#define __TCP_PACKET_H__

#include "addr_ipv4.h"
#include "byte.h"
#include "exception.h"
/*

+----------------------+---------------------+
|         16 bit       |       16 bit        |
+----------------------+---------------------+
|      source port     |  destination port   |
+----------------------+---------------------+
|              sequence number               |
+----------------------+---------------------+
|                 ack number                 |
+----+---------+-------+---------------------+
|head| reserve | flags |     window size     |
+----+---------+-------+---------------------+
|     checksum         |   urgent pointer    |
+----------------------+---------------------+
|     选项              |  填充               |
+----------------------+---------------------+
|              TCP报文段的数据部分             |
+----------------------+---------------------+


*/

class TcpPacket {
public:
    enum {
        // TCP首部固定的20字节
        TCP_HEADER_MIN_LEN = 20
    };
    enum Flags : uint8_t {
        /* 对应的标志位在二进制中位置相对应的数值，这样在进行位运算时会更加直观和方便。
            CWR ECE URG ACK PSH RST SYN FIN
             1   1   1   1   1   1   1   1
        */
        CWR = 128,  // Congestion Window Reduce 拥塞窗口减少标志
        ECE = 64,   // ECN Echo 用来在 TCP 三次握手时表明一个 TCP 端是具备 ECN 功能的
        URG = 32,   // Urgent 表示本报文段中发送的数据是否包含紧急数据
        ACK = 16,   // 表示前面的确认号字段是否有效. ACK=1 时表示有效
        PSH = 8,    // Push 告诉对方收到该报文段后是否立即把数据推送给上层
        RST = 4,    // 表示是否重置连接
        SYN = 2,    // 在建立连接时使用
        FIN = 1,    // 标记数据是否发送完毕
    };

    TcpPacket(const uint8_t *data, uint32_t size) : _data(data), _data_size(size) {
        if (size < TCP_HEADER_MIN_LEN)
            throw std::invalid_argument("invalid tcp packet");
        parse();
    }

    // 检查是否为HTTP方法
    bool is_http_method(const char *data) const {
        static const char *methods[] = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE"};
        for (auto method : methods) {
            if (strncmp(data, method, strlen(method)) == 0)
                return true;
        }
        return false;
    }

    // 检查是否为HTTP状态码
    bool is_http_status(const char *data) const {
        static const char *status_codes[] = {"200", "301", "302", "404", "500"};
        for (auto code : status_codes) {
            if (strncmp(data, code, strlen(code)) == 0)
                return true;
        }
        return false;
    }

    // 检查是否为HTTP响应行特征
    bool is_http_response_line(const char *data) const {
        return strncmp(data, "HTTP/1.1", strlen("HTTP/1.1")) == 0;
    }

    bool is_http_port() const {
        return _target_port == 80 || _source_port == 80;
    }

    // 检查http报文长度有效性
    bool check_http_len() const {
        return _data_size - _header_len;
    }

    bool is_http_protocol(const char *http_data) const {
        return is_http_method(http_data) || is_http_response_line(http_data);
    }
    // 检查是否为HTTP请求或响应
    bool is_http_message() const {
        const char *http_data = (const char *)_data + _header_len;
        if (check_http_len()) {
            // 端口不为80的http报文识别检测
            if (is_http_protocol(http_data))
                return true;

            if (is_http_port())
                return is_http_protocol(http_data);
        }
        return false;
    }

    uint8_t header_len() const noexcept {
        return _header_len;
    }
    // 返回tcp协议上层数据
    const uint8_t *payload() const noexcept {
        // return _data + tcp首部长度
        return _data + _header_len;
    }

    // 上层协议数据包大小
    uint32_t payload_size() const noexcept {
        return _data_size - _header_len;
    }

    // ack位是否有效
    bool is_ack() const {
        return _ack == 1;
    }
    // syn是否有效
    bool is_syn() const {
        return _syn == 1;
    }
    // 返回目标端口
    uint16_t target_port() const {
        return _target_port;
    }
    void parse() {
        const uint8_t *tcp_data = _data;
        _source_port = as_host<uint16_t>(tcp_data);
        tcp_data += 2;
        _target_port = as_host<uint16_t>(tcp_data);
        tcp_data += 2;
        _seq_num = as_host<uint32_t>(tcp_data);
        tcp_data += 4;
        _ack_num = as_host<uint32_t>(tcp_data);
        tcp_data += 4;
        _flags = as_host<uint16_t>(tcp_data);
        _header_len = ((_flags & 0xf000) >> 12) * 4;
        _reserve = (_flags & 0x0fC0) >> 6;
        _urg = (_flags & 0x0020) >> 5;
        _ack = (_flags & 0x0010) >> 4;
        _syn = (_flags & 0x0002) >> 1;
        tcp_data += 2;
        _window = as_host<uint16_t>(tcp_data);
        tcp_data += 2;
        _checksum = as_host<uint16_t>(tcp_data);
        tcp_data += 2;
        _urgent_pointer = as_host<uint16_t>(tcp_data);
        tcp_data += 2;
    }

    void debug_info() {
        printf(" source port: %u\n target port: %u\n Sequence Number: %u\n Acknowledgment Number: %u\n",
               _source_port, _target_port, _seq_num, _ack_num);
        printf(" header len: %u bytes\n reserve: %u\n flags: %#x\n urg: %u\n syn: %u\n ack: %u\n",
               _header_len, _reserve, _flags, _urg, _syn, _ack);
        printf(" window size: %u\n check sum: %#x\n urgent pointer: %u\n",
               _window, _checksum, _urgent_pointer);
    }

private:
    uint16_t _source_port{0};  // 源端口
    uint16_t _target_port{0};  // 源端口
    uint32_t _seq_num{0};      // 序号
    uint32_t _ack_num{0};      // 确认号
    uint8_t _header_len{0};    // tcp头部长度/数据偏移，得到tcp报文段中 数据起始处 距离 tcp报文段起始处的 偏移量
    uint8_t _reserve{0};       // 保留字段，6位
    uint8_t _urg{0};           // URG字段，1位
    uint8_t _syn{0};           // SYN字段，1位
    uint8_t _ack{0};           // ACK字段，1位

    uint16_t _window{0};          // 窗口字段，指明窗口大小
    uint16_t _checksum{0};        // 校验和
    uint16_t _urgent_pointer{0};  // 紧急指针，当URG标志位为1才有意义
    uint16_t _flags{0};           // 保留6个控制位
    const uint8_t *_data;         // tcp报文段起始地址
    uint32_t _data_size;          // tcp报文段总大小
};

#endif  // __TCP_PACKET_H__
