#ifndef __DNS_VIEW_H__
#define __DNS_VIEW_H__

/*
dns协议报文格式
+--------------------------+---------------------------+
|           16 bit         |1b|4bit|1b|1b|1b|1b|3b|4bit|
+--------------------------+--+----+--+--+--+--+--+----+
|      identification      |QR| OP |AA|TC|RD|RA|..|Rcod|
+--------------------------+--+----+--+--+--+--+--+----+
|         Question         |       Answer RRs          |
+--------------------------+---------------------------+
|     Authority RRs        |      Additional RRs       |
+--------------------------+---------------------------+
|           Queries (查询问题区域)                      |
+--------------------------+---------------------------+
|           Answers (回答区域)                          |
+--------------------------+---------------------------+
|           Authoritative nameservers (授权区域)        |
+--------------------------+---------------------------+
|           Additional recoreds (附加区域)              |
+--------------------------+---------------------------+

Queries (查询问题区域)
+--------------------------+---------------------------+
|           16 bit         |  16 bit                   |
+--------------------------+---------------------------+
|            Name（查询名，长度不固定）                  |
+--------------------------+---------------------------+
|          Type(查询类型)   |    Class(查询类)          |
+--------------------------+---------------------------+


*/
#include <vector>
#include "exception.h"
#include "byte.h"
#include "addr_ipv4.h"
/*
TODO:
1. 完成问题区域和资源记录区域公共部分的解析
    1.1 类内成员、如何构造
    1.2 如何解析查询名
    1.3 查询类及查询类型对应的值和说明

*/

// dns报文中 QR标志、opcode、查询类型
enum class DNSFlags
{

    /* dns头部opcode  */

    DNS_OPCODE_STANDARD_QUERY = 0, // 标准查询
    DNS_OPCODE_OPPOSITE_QUERY = 1, // 反向查询

    /* dns数据区域查询类型  */

    DNS_QUERY_TYPE_A = 1,     // 由域名获得ipv4地址 (A)
    DNS_QUERY_TYPE_CNAME = 5, // 查询规范名称 (CNAME)
    DNS_QUERY_TYPE_SOA = 6,   // 开始授权 (SOA)
    DNS_QUERY_TYPE_PTR = 12,  // 把IP地址转换成域名 (PTR)
    DNS_QUERY_TYPE_AAAA = 28  // 由域名得到ipv6地址(AAAA)
};

// 资源区域 公共部分
class ResourceBase
{
public:
    ResourceBase(const uint8_t *data, uint16_t offset) : _dns(data)
    {
        _type = _class = _qname_len = _total_len = 0;
        _offset = offset;
        // parse_query_data();
        // parse_qname(offset);
    }

    DNSFlags type() const noexcept
    {
        return (DNSFlags)_type;
    }

    // 查询类型是否为A
    bool is_ipv4() const noexcept
    {
        return type() == DNSFlags::DNS_QUERY_TYPE_A;
    }

    // 查询类型是否为CNAME
    bool is_cname() const noexcept
    {
        return type() == DNSFlags::DNS_QUERY_TYPE_CNAME;
    }
    // 返回域名字符串
    const std::string &qname() const noexcept
    {
        return _qname;
    }
    // 返回查询类型
    uint16_t qtype() const noexcept
    {
        return _type;
    }

    // 返回查询类
    uint16_t qclass() const noexcept
    {
        return _class;
    }
    // 返回域名的总长度，如.www.qq.com.
    uint16_t qname_len() const noexcept
    {
        return _qname_len;
    }

    // 返回该条资源记录的总长度
    virtual uint16_t total_len() const noexcept
    {
        return _total_len;
    }

    // 调试，输出查询问题区域解析的内容
    void debug_query_info()
    {
        std::cout << " qname: " << _qname << std::endl;
        // printf(" qname: %s\n type: %u\n class: %u\n", _qname.c_str(), _type, _class);
        printf(" type: %u\n class: %u\n", _type, _class);
        printf(" qname len: %u\n total len: %u\n", _qname_len, _total_len);
    }

protected:
    void parse_query_data()
    {
        const uint8_t *data = _dns;
        // 解析查询名(域名)
        parse_qname(data, _offset);
        // 解析查询类型和查询类
        data += (_qname_len + _offset);
        _type = as_host<uint16_t>(data);
        data += 2;
        _class = as_host<uint16_t>(data);
        _total_len = _qname_len + 2 + 2;
    }

    /*
        在解析DNS报文中的域名字段时，不需要考虑网络字节序的问题。DNS协议规定了域名字段的编码方式，以.作为标签之间的分隔符，
        标签的长度和内容都是以字节为单位按顺序存储的。因此，解析域名字段时只需要按照协议规定的格式依次读取字节，并根据.的位置
        和长度信息来识别每个标签的内容，直到遇到.表示域名结束为止。
    */
    void parse_qname(const uint8_t *dns_data, uint16_t offset = 0)
    {
        // dns_data = _dns;
        //  域名的部分域名（标号）最大长度是64
        //  dns域名总长度不超过255
        _qname.reserve(255);
        _qname.clear();
        _qname_len = 0;                 // 重置长度，因为可能资源记录区域先解析前面的域名，此时qname_len保存的是前面的域名长度
        bool found_ptr = false;         // 是否为偏移指针
        auto pos = offset;              // dns报文偏移，在这里指向重复域名/查询名所在的位置
        uint8_t len = dns_data[offset]; // 得到第一个部分域名的长度，在这里也可能表示偏移指针高位字节的数据
        while (len != 0)
        {
            if (is_pointer(len))
            {
                // 获取到重复域名在dns报文的偏移量
                pos = as_host<uint16_t>(dns_data + pos) & 0x3fff;
                len = dns_data[pos];
                found_ptr = true;
                continue;
            }
            /*
            冷知识 ：DNS 报文中每个域名部分的开头(.)都是一个表示长度的字节，表示当前部分域名（标号）的长度
            */
            _qname.append((char *)dns_data + pos + 1, len);
            // 如果是偏移指针，此时_qname_len不变，否则需要加上len域名部分长度，+1表示域名前面的"."
            found_ptr ? _qname_len : _qname_len += (len + 1);

            pos += (len + 1); // 移动到下一个.,获取下一个部分域名的长度
            len = dns_data[pos];
            if (len != 0)
                _qname.append(".");
        }
        // 如果不是偏移指针，域名还需加上最后一个点的长度,否则是两个指针字节大小
        found_ptr ? _qname_len += 2 : _qname_len += 1;
    }

    // 检查是否为偏移指针
    bool is_pointer(uint8_t value) const noexcept
    {
        return ((value >> 6) & 0x03) == 0x03;
    }

protected:
    std::string _qname{}; // 查询名/域名字符串
    uint16_t _type;       // 查询类型
    uint16_t _class;      // 查询类
    uint16_t _qname_len;  // 查询名/域名长度
    uint16_t _total_len;  // 该资源区域的总长度

    const uint8_t *_dns; // dns报文的起始地址
    uint16_t _offset;    // 相对dns报文开始位置的偏移量
};

// 问题查询区域
class QueryResource : public ResourceBase
{
public:
    using ResourceBase::ResourceBase;
    void parse_query()
    {
        parse_query_data();
    }
};

// 回答区域
class ResponseResource : public ResourceBase
{
public:
    // 使用基类的构造函数代替本类构造函数
    using ResourceBase::ResourceBase;
    uint16_t total_len() const noexcept
    {
        return _qname_len + 2 + 2 + 4 + 2 + _resource_data_len;
    }

    // 返回ipv4地址
    AddrIPv4 ipv4_addr() const noexcept
    {
        if (is_ipv4())
            return AddrIPv4{as<uint32_t>(_dns + _offset + _qname_len + 2 + 2 + 4 + 2)};
        return {};
    }

    std::string cname() const noexcept
    {
        return _cname;
    }

    // 解析整个资源记录区域
    void parse_response()
    {
        // 解析公共区域
        parse_query_data();
        const uint8_t *res_data = _dns;
        res_data = res_data + _offset + _qname_len + 2 + 2;
        _ttl = as_host<uint32_t>(res_data);
        res_data += 4;
        _resource_data_len = as_host<uint16_t>(res_data);
        // 解析资源数据
        if (is_cname())
        {
            parce_cname(_offset + _qname_len + 2 + 2 + 4 + 2);
        }
        else if (is_ipv4())
        {
            _cname = ipv4_addr().to_string();
        }
    }

    void debug_res_info()
    {
        debug_query_info();
        printf(" ttl: %u\n data len: %u\n", _ttl, _resource_data_len);
        printf(" total len: %u\n qname_len: %u\n", total_len(), qname_len());
        if (is_cname())
        {
            printf(" cname: %s\n", _cname.c_str());
        }
        else if (is_ipv4())
        {
            printf(" ip address: %s\n", _cname.c_str());
        }
    }

private:
    // 解析资源记录区域的资源数据
    void parce_cname(uint16_t offset)
    {
        _cname.reserve(255);
        // parse_qname(_dns, offset);
        // _cname = qname();
        auto pos = offset;
        uint8_t len = _dns[pos];
        while (len != 0)
        {
            if (is_pointer(len))
            {
                pos = as_host<uint16_t>(_dns + pos) & 0x3fff;
                len = _dns[pos];
                continue;
            }
            _cname.append((char *)_dns + pos + 1, len);
            pos += (len + 1);
            len = _dns[pos];
            if (len != 0)
                _cname.append(".");
        }
    }

    uint32_t _ttl{0};               // 生存时间
    uint16_t _resource_data_len{0}; // 资源数据长度
    std::string _cname{};           // 资源数据（域名）
};

class DnsView
{
public:
    enum
    {
        DNS_HEADER_LEN = 12, // dns头部长度，固定12字节
        PORT = 53,           // dns协议使用的端口

        /* dns头部QR标志  */

        DNS_QUERY_FLAG = 0,   // 查询标志
        DNS_RESPONSE_FLAG = 1 // 响应标志
    };

    DnsView(const uint8_t *data, uint32_t size) : _data(data)
    {
        if (size < DNS_HEADER_LEN)
            throw std::invalid_argument("invalid dns packet");
        // 在构造中执行解析操作
        parse_dns_header();
    }

    void parse_dns_header()
    {
        const uint8_t *dns_data = _data;
        _transaction_id = as_host<uint16_t>(dns_data);
        dns_data += 2;

        /* 解析flags，得到每个标志 */
        uint16_t flags = as_host<uint16_t>(dns_data);
        // printf("flags: 0x%04x\n", flags);
        _is_response = (flags & 0x8000) >> 15;
        _op_code = (flags & 0x7800) >> 11;
        _is_authenticated_answer = (flags & 0x0400) >> 10;
        _is_truncated = (flags & 0x0200) >> 9;
        _is_recursion_disired = (flags & 0x0100) >> 8;

        _is_recursion_available = (flags & 0x0080) >> 7;
        _reply_code = (flags & 0x000f);
        dns_data += 2;
        _question_amount = as_host<uint16_t>(dns_data);
        dns_data += 2;
        _answer_amount = as_host<uint16_t>(dns_data);
        dns_data += 2;
        _authority_amount = as_host<uint16_t>(dns_data);
        dns_data += 2;
        _additional_amount = as_host<uint16_t>(dns_data);
        dns_data += 2;

        // 解析区域
        parse_res_data(_data);
    }

    void parse_res_data(const uint8_t *data)
    {
        // 解析查询问题区域
        _query_list.reserve(_question_amount);
        uint16_t offset = DNS_HEADER_LEN; // 表示dns报文起始的偏移量
        for (uint16_t i = 0; i < _question_amount; i++)
        {
            QueryResource query(data, offset);
            query.parse_query();
            offset += query.total_len();
            _query_list.push_back(std::move(query));
        }
        // 如果是dns查询报文
        if (is_query())
            return;

        // 解析回答区域资源
        _response_list.reserve(_answer_amount);
        for (uint16_t i = 0; i < _answer_amount; i++)
        {
            ResponseResource response(data, offset);
            response.parse_response();
            offset += response.total_len();
            _response_list.push_back(std::move(response));
        }

        // 解析授权区域（如果有）
        _authority_list.reserve(_authority_amount);
        for (uint16_t i = 0; i < _authority_amount; i++)
        {
            ResponseResource authority(data, offset);
            authority.parse_response();
            offset += authority.total_len();
            _authority_list.push_back(std::move(authority));
        }

        // 解析附加区域（如果有）
        _additional_list.reserve(_additional_amount);
        for (uint16_t i = 0; i < _additional_amount; i++)
        {
            ResponseResource additional(data, offset);
            additional.parse_response();
            offset += additional.total_len();
            _additional_list.push_back(std::move(additional));
        }
    }

    // 是否为dns响应报文
    bool is_response() const noexcept
    {
        return _is_response;
    }
    // 是否为dns请求报文
    bool is_query() const noexcept
    {
        return !is_response();
    }

    // 请求资源列表
    const std::vector<QueryResource> &query_list() const
    {
        return _query_list;
    }
    // 回答资源列表
    const std::vector<ResponseResource> &response_list() const
    {
        return _response_list;
    }

    void debug_header_info()
    {
        printf(" transaction id: %#x\n", _transaction_id);
        printf(" Flags:\n is response: %u\n opcode: %u\n AA: %u\n TC: %u\n RD: %u\n RA: %u\n rcode: %u\n",
               _is_response, _op_code, _is_authenticated_answer, _is_truncated, _is_recursion_disired, _is_recursion_available, _reply_code);
        printf(" Questions: %u\n Answer RRs: %u\n Authority RRs: %u\n Additional RRs: %u\n",
               _question_amount, _answer_amount, _authority_amount, _additional_amount);
    }
    // 输出dns协议的所有内容
    void debug_info()
    {
        std::string QR[] = {"查询", "响应"};
        printf("DNS%s: \n", QR[_is_response].c_str());
        // debug_header_info();
        printf("Query: \n");
        for (auto it : _query_list)
        {
            // it.debug_query_info();
            std::cout << it.qname() << ", ";
        }
        printf("\n");
        if (_is_response)
        {
            printf("Answers: \n");
            for (auto it : _response_list)
            {
                // it.debug_res_info();
                std::cout << it.cname() << ", ";
            }
            printf("\n");
        }
    }

private:
    const uint8_t *_data; // dns报文起始地址
    /* dns头 */
    uint16_t _transaction_id{0}; // 会话标识

    uint8_t _is_response{0};             // QR：查询 / 响应标志
    uint8_t _op_code{0};                 // 操作
    uint8_t _is_authenticated_answer{0}; // AA,应答是否为该域名的权威解析服务器

    uint8_t _is_truncated{0};           // TC,是否截断
    uint8_t _is_recursion_disired{0};   // RD,期望递归
    uint8_t _is_recursion_available{0}; // RA,可用递归
    uint8_t _reply_code{0};             // 返回码

    uint16_t _question_amount{0};   // 查询区域数量
    uint16_t _answer_amount{0};     // 回答区域数量
    uint16_t _authority_amount{0};  // 授权区域数量
    uint16_t _additional_amount{0}; // 附加区域数量

    std::vector<QueryResource> _query_list;         // 查询区域列表
    std::vector<ResponseResource> _response_list;   // 回答区域列表
    std::vector<ResponseResource> _authority_list;  // 授权区域列表
    std::vector<ResponseResource> _additional_list; // 附加区域列表
};

#endif //__DNS_VIEW_H__
