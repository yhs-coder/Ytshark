#ifndef __HTTP_MESSAGE_H__
#define __HTTP_MESSAGE_H__

#include <iostream>
#include <map>
#include <sstream>
#include <cctype>
#include <vector>
#include <algorithm> // 包含 std::transform 函数
#include "exception.h"

// 定义HTTP头部字段的键值对
using HttpHeaders = std::map<std::string, std::string>;

// 定义http请求，响应的通用结构
class HttpMessage
{
public:
    HttpMessage() = default;
    ~HttpMessage() = default;

    std::string _start_line;  // 用于存储请求的起始行或响应的状态行
    std::string _headers_str; // 存储首部字段全部的内容
    std::string _body;        // 存储请求行或响应体
    // HttpHeaders _headers;     // 存储首部字段和值的映射关系

    void value_to_string(std::string &http_data_str)
    {
        // 将http报文中的请求行/响应行、首部字段、请求体/响应体 分别存入_http_message中
        size_t request_line_pos = http_data_str.find("\r\n"); // 找到第一个\r\n
        if (request_line_pos != std::string::npos)
            _start_line = http_data_str.substr(0, request_line_pos); // 保存请求行/响应行的内容

        size_t headers_end_pos = http_data_str.find("\r\n\r\n"); // http头部字段到空行结束
        if (headers_end_pos != std::string::npos)
        {
            // 保存http首部字段
            _headers_str = http_data_str.substr(request_line_pos + 2, headers_end_pos);
            _body = http_data_str.substr(headers_end_pos + 4);
        }
    }
};

class HttpRequest : public HttpMessage
{
public:
    HttpRequest() = default;

    // 解析http请求行
    void parse_http_request_line()
    {
        std::istringstream request_line_stream(_start_line);
        std::getline(request_line_stream, _method, ' ');
        std::getline(request_line_stream, _path, ' ');
        std::getline(request_line_stream, _http_version, ' ');
    }

    std::string _method;       // 请求方法
    std::string _path;         // 请求资源路径
    std::string _http_version; // http版本
};

class HttpResponse : public HttpMessage
{
public:
    HttpResponse() = default;
    void parse_http_request()
    {
    }

    // 解析http响应行
    void parse_http_response_line()
    {
        std::istringstream request_line_stream(_start_line);
        std::getline(request_line_stream, _http_version, ' ');
        std::getline(request_line_stream, _status_code, ' ');
        std::getline(request_line_stream, _phrase, ' ');
    }

    std::string _http_version; // http版本
    std::string _status_code;  // 响应码
    std::string _phrase;       // 响应描述
};

// HTTP协议解析器
class HttpParser
{
public:
    HttpParser(const uint8_t *http_data, uint32_t size)
        : _http_data(http_data), _size(size)
    {
        if (_http_data == nullptr || _size == 0)
            throw std::invalid_argument("invalid http data!");
        parse_http();
    }
    ~HttpParser()
    {
    }
    std::string request_mothod() const
    {
        return _request._method;
    }
    std::string request_path() const
    {
        return _request._path;
    }
    // 是否为http请求报文
    bool is_http_request()
    {
        static const char *methods[] = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE"};
        for (auto method : methods)
        {
            if (strncmp((const char *)_http_data, method, strlen(method)) == 0)
                return true;
        }
        return false;
    }

    // 解析http报文
    void parse_http()
    {
        // 将整个HTTP报文转换为字符串
        std::string http_data_str = bytes_to_string(_http_data, _size);
        // 判断http报文类型
        _is_request = is_http_request();
        if (_is_request)
        {
            _request.value_to_string(http_data_str);
            // 解析开始行
            _request.parse_http_request_line();
            // 解析HTTP头部字段
            _headers = parse_headers(_request._headers_str);
        }
        else
        {
            _response.value_to_string(http_data_str);
            // 解析开始行
            _response.parse_http_response_line();
            // 解析HTTP头部字段
            _headers = parse_headers(_response._headers_str);
        }
    }

    void print_http_message() const
    {
        std::cout << "开始行:" << std::endl;
        if (_is_request)
        {
            std::cout << "method: " << _request._method << std::endl;
            std::cout << "path: " << _request._path << std::endl;
            std::cout << "http version: " << _request._http_version << std::endl;
            std::cout << "http头部字段" << std::endl;
            for (const auto &header : _headers)
            {
                std::cout << header.first << " :" << header.second << std::endl;
            }
            if (!_request._body.empty())
            {
                std::cout << "请求实体内容：" << std::endl;
                std::cout << _request._body << std::endl;
            }
        }
        else
        {
            std::cout << "http version: " << _response._http_version << std::endl;
            std::cout << "status code: " << _response._status_code << std::endl;
            std::cout << "phrase: " << _response._phrase << std::endl;
            std::cout << "http头部字段" << std::endl;
            for (const auto &header : _headers)
            {
                std::cout << header.first << " :" << header.second << std::endl;
            }
        }
    }

private:
    // 将字节数据转换为字符串
    std::string bytes_to_string(const uint8_t *data, uint32_t size)
    {
        return std::string((const char *)data, size);
    }

    // 解析HTTP头部字段，存储在map中
    std::map<std::string, std::string> parse_headers(const std::string &header_str)
    {
        std::map<std::string, std::string> headers;
        std::istringstream header_stream(header_str); // 读取header_str字符串的内容
        std::string line;                             // 存储每行读取到的字符串
        // 逐行读取头部字段，直到遇到空行，表示头部结束
        while (std::getline(header_stream, line) && !line.empty())
        {
            size_t pos = line.find(':'); // 找到分隔符':', header字段名: 值
            if (pos != std::string::npos)
            {
                std::string header_name = line.substr(0, pos);   // 字段名
                std::string header_value = line.substr(pos + 1); // 字段值
                // 使用大小写无关的方式来处理头部字段
                // 将容器 header_name 中的所有字符转换为小写字母。
                std::transform(header_name.begin(), header_name.end(), header_name.begin(), ::tolower);
                headers[header_name] = header_value; // 字段和值映射
            }
        }
        return headers;
    }

private:
    HttpRequest _request;    // http请求报文
    HttpResponse _response;  // http响应报文
    bool _is_request = true; // 默认为http请求报文
    // std::map<std::string, std::string> _headers{};
    HttpHeaders _headers;      // 存储首部字段和值的映射关系
    const uint8_t *_http_data; // http报文起始地址
    uint32_t _size;
};
#endif
