#ifndef __DNS_H__
#define __DNS_H__ 

#include "base.h"
#include "protocol.h"
#include <vector>

using namespace std;

#define DNS_PORT                    53      // dns协议端口
#define DNS_HEADER_SIZE             12      // dns报文头部字节长度
#define DNS_DOMAIN_MAX_SIZE         0xFF    // dns域名总长度不超过255
#define DNS_DOMAIN_BUFFER_SIZE      (DNS_DOMAIN_MAX_SIZE + 1)   // dns域名数组最大总长度

#define DNS_QUERY_NAME_MIN_SIZE     2       // dns查询域名最小数据长度（当报文中域名重复出现的时候）

/* dns头部QR标志  */
#define DNS_QUERY_FLAG              false   // 查询标志
#define DNS_RESPONSE_FLAG           true    // 响应标志

/* dns头部opcode  */
#define DNS_OPCODE_STANDARD_QUERY            0   // 标准查询
#define DNS_OPCODE_OPPOSITE_QUERY            1   // 反向查询
#define DNS_OPCODE_REQUEST_SERVER_STATE      2   // 服务器状态请求
#define DNS_OPCODE_NOTIFY                    4   // 通知
#define DNS_OPCODE_UPDATE                    5   // 更新
#define IS_VALID_DNS_OPCODE(value)           ((value) == DNS_OPCODE_STANDARD_QUERY || (value) == DNS_OPCODE_OPPOSITE_QUERY  \
                                             || (value) == DNS_OPCODE_REQUEST_SERVER_STATE || (value) == DNS_OPCODE_NOTIFY || \
                                             (value) == DNS_OPCODE_UPDATE)

/* dns数据区域查询类型  */
#define DNS_QUERY_TYPE_A                1       // 由域名获得ipv4地址 (A)
#define DNS_QUERY_TYPE_NS               2       // 查询域名服务器 (NS)
#define DNS_QUERY_TYPE_CNAME            5       // 查询规范名称 (CNAME)
#define DNS_QUERY_TYPE_SOA              6       // 开始授权 (SOA)
#define DNS_QUERY_TYPE_WKS              11      // 熟知服务(WKS)
#define DNS_QUERY_TYPE_PTR              12      // 把IP地址转换成域名 (PTR)
#define DNS_QUERY_TYPE_HINFO            13      // 主机信息(HINFO)
#define DNS_QUERY_TYPE_MX               15      // 邮件交换(MX)
#define DNS_QUERY_TYPE_AAAA             28      // 由域名得到ipv6地址(AAAA)
#define DNS_QUERY_TYPE_AXFR             252     // 传送整个区的请求(AXFR)
#define DNS_QUERY_TYPE_ANY              255     // 对所有记录的请求(ANY)
#define IS_VALID_DNS_QUERY_TYPE(type)   ((value) == DNS_QUERY_TYPE_A || (value) == DNS_QUERY_TYPE_NS || \
                                        DNS_QUERY_TYPE_CNAME || (value) ==DNS_QUERY_TYPE_SOA || (value) == DNS_QUERY_TYPE_WKS || \
                                        (value) == DNS_QUERY_TYPE_PTR || (value) == DNS_QUERY_TYPE_HINFO || \
                                        (value) == DNS_QUERY_TYPE_MX || (value) == DNS_QUERY_TYPE_AAAA || \
                                        (value) == DNS_QUERY_TYPE_AXFR || (value) == DNS_QUERY_TYPE_ANY)

/* DNS头部返回码 */
#define DNS_REPLY_CODE_SUCCESS          0       // 没有差错
#define DNS_REPLY_CODE_NAME_ERROR       1       // 名字差错
#define DNS_REPLY_CODE_SERVER_ERROR     2       // 服务器差错
#define DNS_REPLY_CODE_NX_DOMAIN        3       // 不存在域名
#define DNS_REPLY_CODE_NOTLMP           4       // 未实现
#define DNS_REPLY_CODE_REFUSED          5       // 查询拒绝
#define IS_VALID_DNS_REPLY_CODE(value)  ((value) == DNS_REPLY_CODE_SUCCESS || (value) == DNS_REPLY_CODE_NAME_ERROR || \
                                        (value) == DNS_REPLY_CODE_SERVER_ERROR || (value) == DNS_REPLY_CODE_NX_DOMAIN || \
                                        (value) == DNS_REPLY_CODE_NOTLMP || (value) == DNS_REPLY_CODE_REFUSED)

/* DNS查询类  */
#define DNS_QUERY_CLASS_IN              1       // internet数据
#define IS_VALID_DNS_QUERY_CLASS(value) ((value) == DNS_QUERY_CLASS_IN)

/* DNS解析数据的类型  */
#define DNS_PARSE_DATA_TYPE_UNDEFINED   0       // 未定义
#define DNS_PARSE_DATA_TYPE_IPV4        1       // IPV4
#define DNS_PARSE_DATA_TYPE_DOMAIN      2       // 域名
#define DNS_PARSE_DATA_TYPE_IPV6        3       // ipv6
#define IS_VALID_DNS_PARSE_DATA_TYPE(type)      ((type) == DNS_PARSE_DATA_TYPE_IPV4 || (type) == DNS_PARSE_DATA_TYPE_DOMAIN)

/* DNS查询名字段 **/
#define IS_DNS_CNAME_OFFSET_PTR(value)          (((value) & 0xC0) == 0xC0)  // dns查询名是否为指针偏移
#define DNS_CNAME_OFFSET_GETTER(value)          ((value) & 0x3FFFF)         // dns查询名偏移获取 uint16_t

/* dns头部数据获取  */
#define DNS_QR_FLAG_GETTER(byte)                        (((byte) & 0x80) > 0)       // dns头QR标志获取，bool
#define DNS_OPCODE_GETTER(byte)                         (((byte) & 0x78) >> 3)      // dns头opcode获取，uint8_t
#define DNS_AUTHENTICATED_ANSWER_FLAG_GETTER(byte)      (((byte) & 0x04) > 0)       // dns头AA标志位获取，bool
#define DNS_TRUNCATED_FLAG_GETTER(byte)                 (((byte) & 0x02) > 0)       // dns头部TC标志位获取，bool
#define DNS_RECURSION_DISIRED_FLAG_GETTER(byte)         (((byte) & 0x01) > 0)       // dns头部RD标志位获取，bool
#define DNS_RECURSION_AVAILABLE_FLAG_GETTER(byte)       (((byte) & 0x80) > 0)       // dns头部RA标志位获取，bool
#define DNS_REPLY_CODE_GETTER(byte)                     (((byte) & 0x0f))           // dns头返回码获取，uint8_t


// Query区域中查询名，域名、ip地址及ipv6地址
union Qname
{
    // 查询名长度不确定，直接把缓冲区取到域名最大长度
    uint8_t domain[DNS_DOMAIN_BUFFER_SIZE];
    uint32_t ip;
    uint8_t ipv6[IPV6_COMMON_SIZE];
    void debug_info(int data_byte);
};

/* DNS查询区域和资源记录区域的公共部分 */
class DnsAreaPublic
{
public:
    Qname _name;            // 查询名
    uint16_t _query_type;   // 查询类型
    uint16_t _query_class;  // 查询类
    uint32_t _size;         // 总长度，为实际在数据包中的字节长度
    uint32_t _data_type;    // 实际数据类型

    int parse(void *dns_start, uint32_t dns_size, uint32_t offset, int parse_data_type);
    void reset();
    void debug_info();
};

/* dns资源记录区域  */
class DnsResRecordArea
{
public:
    DnsAreaPublic _query_data;
    uint32_t _ttl;              // dns缓存实践(s)
    uint16_t _res_data_size;    // 资源数据长度
    Qname _res_data;            // 资源数据
    uint32_t _size;             // 总长度，为实际在数据包中的字节长度

    int parse(void *dns_start, uint32_t dns_size, uint32_t offset, int parse_data_type);
    void reset();
    void debug_info();
    // 获取资源数据的类型
    int get_resource_data_type();   
};

/* dns数据包 */
class Dns : public Protocol 
{
public:
    /* dns头 */
    uint16_t _transaction_id;           // 会话标识
    
    bool _is_response;                  // 查询 / 响应标志
    uint8_t _op_code;                   // 操作
    bool _is_authenticated_answer;      // AA,应答是否为该域名的权威解析服务器

    bool _is_truncated;                 // TC,是否截断
    bool _is_recursion_disired;         // RD,期望递归
    bool _is_recursion_available;       // RA,可用递归
    uint8_t _reply_code;                // 返回码

    uint16_t _question_amount;          // 查询区域数量
    uint16_t _answer_amount;            // 回答区域数量
    uint16_t _authority_amount;         // 授权区域数量
    uint16_t _additional_amount;        // 附加区域数量

    vector<DnsAreaPublic> _questions;
    vector<DnsResRecordArea> _answers;
    vector<DnsResRecordArea> _authoritys;
    vector<DnsResRecordArea> _additionals;

    Dns();
    ~Dns();

    bool is_valid_dns_header();
    int parse_dns_data_area(void *dns_start, uint32_t size);

    virtual const std::type_info &get_class_type_info();
    bool check_buffer_length(void *buffer, uint32_t size);
    int parse(void *buffer, uint32_t size);
    int opposite_byte();
    int debug_info();
   
    static int parse_dns_qname(void *dns_start, uint32_t dns_size, uint32_t offset, Qname &data, int parse_data_type);
    static int parse_dns_domain(void *dns_start, uint32_t dns_size, uint32_t offset, uint8_t *data);
};

#endif 
