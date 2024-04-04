#include "dns.h"

void Qname::debug_info(int data_type)
{
    switch (data_type)
    {
        // 数据类型是ipv地址
        case DNS_PARSE_DATA_TYPE_IPV4:
            {
                struct in_addr addr;
                addr.s_addr = this->ip;
                char *ipv4_str = inet_ntoa(addr);
                if (ipv4_str != NULL)
                {
                    printf("%s", ipv4_str);
                }
            }
            break;
        case DNS_PARSE_DATA_TYPE_DOMAIN:
            printf("%s", this->domain);
            break;
        default:
            printf("unknown");
    }
}

/*
 *  重置成员
 * */
void DnsAreaPublic::reset()
{
    _query_type = _query_class = 0;
    _size = 0;
    _data_type = DNS_PARSE_DATA_TYPE_UNDEFINED;
}

/*
 * 解析dns查询名，查询类型、查询类
 * @param dns_start -- dns报文起始
 * @param dns_size  -- dns报文总长度
 * @param offset    -- 在dns报文中的偏移
 * return ErrorCode
 * */
int DnsAreaPublic::parse(void *dns_start, uint32_t dns_size, uint32_t offset, int parse_data_type)
{
    JUDGE_RETURN(dns_start == nullptr || offset >= dns_size, DNS_PARSE_DATA_TYPE_ARGS);
    JUDGE_RETURN(!IS_VALID_DNS_PARSE_DATA_TYPE(parse_data_type), DNS_PARSE_ERRPR_UNSPPORTED_DATA_TYPE);
    // 判断字节序是否为小端
    bool is_opposite = get_endian() ==LITTLE_ENDIAN;    
    u_char *data = (u_char*)dns_start + offset;
    reset();
    _size = Dns::parse_dns_qname(dns_start, dns_size, offset, _name, parse_data_type);
    JUDGE_RETURN(_size <= 0, DNS_PARSE_ERROR_PARSE_DOMAIN);
    _data_type = parse_data_type;

    /* 查询类型和查询类  */
    data += _size;
}
