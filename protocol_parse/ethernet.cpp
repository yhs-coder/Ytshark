#include "ethernet.h"

EthernetHeader::EthernetHeader(bool is_opposite_byte)
    : Protocol(is_opposite_byte)
{
    memset(_preamble, ETHERNET_PREAMBLE_VALUE,ETHERNET_PREAMBLE_BYTE);
    _sfd = ETHERNET_SFD_VALUE;
    memset(_target_mac, 0 , ETHERNET_MAC_BYTE);
    memset(_source_mac, 0 , ETHERNET_MAC_BYTE);
    _type = 0;
    _size = ETHERNET_HEADER_MIN_BYTE; 
}

EthernetHeader::~EthernetHeader()
{}

/*
 * @以buffer起始地址作为以太网数据包头，检查受否有前导码和帧开始符
 * @return bool 
 * */
bool EthernetHeader::is_have_preamble_and_sfd(void *buffer, uint32_t size)
{
    if (size < ETHERNET_PREAMBLE_BYTE + ETHERNET_SFD_BYTE)
        return false;
    u_char *cbuffer = (u_char*)buffer;
    return (memcmp(cbuffer, _preamble, ETHERNET_PREAMBLE_VALUE) == 0) && (*(cbuffer + ETHERNET_PREAMBLE_VALUE) == _sfd);
}

bool EthernetHeader::is_protocol_type()
{
    switch(_type)
    {
        // 类型定义在/usr/include/net/ethernet.h文件中
        case ETHERTYPE_IP:
        case ETHERTYPE_ARP:
        case ETHERTYPE_REVARP:
        case ETHERTYPE_AT:
        case ETHERTYPE_AARP:
        case ETHERTYPE_VLAN:
        case ETHERTYPE_IPV6:
        case ETHERTYPE_LOOPBACK:
            return true;
        default:
            return false;
    }
}

bool EthernetHeader::check_buffer_length(void *buffer, uint32_t size)
{
    if (is_have_preamble_and_sfd(buffer, size))
        return size >= ETHERNET_HEADER_MAX_BYTE;
    return false;
}

int EthernetHeader::parse(void *buffer, uint32_t size)
{
    JUDGE_RETURN(!check_buffer_length(buffer,size), ETHERNET_PARSE_ERROR_MIN_LENGTH);

    u_char *skip_buffer = (u_char*)buffer;
    if (is_have_preamble_and_sfd(buffer, size))
    {
        // 指针挪动（前导值+SFD）个字节，指向DST字段
        skip_buffer += ETHERNET_PREAMBLE_BYTE + ETHERNET_SFD_BYTE;
        _size = ETHERNET_HEADER_MAX_BYTE;
    }

    memcpy(&(_target_mac), skip_buffer, ETHERNET_MAC_BYTE); 
    // 移动skip_buffer,指向SRC字段
    skip_buffer += ETHERNET_MAC_BYTE;
    memcpy(&(_source_mac), skip_buffer, ETHERNET_MAC_BYTE); 
    skip_buffer += ETHERNET_MAC_BYTE;
    memcpy(&(_type), skip_buffer, sizeof(_type));
    // 因为以太网数据包的字节序为网络字节序
    // _type整数字节序 与 ethernet.h定义的协议号类型相反
    // 需要反转字节序
    _type = OPPOSIZE_SHORT_ORDER(_type);

    _is_opposite_byte ? opposite_byte() : 1;
    return is_protocol_type() ? PARSE_SUCCESS : ETHERNET_PARSE_ERROR_PROTOCOL_TYPE;
}

int EthernetHeader::opposite_byte()
{
    _type = OPPOSIZE_SHORT_ORDER(_type);
    return 0;
}

int EthernetHeader::debug_info()
{
    /* 默认不输出前导符和帧开始符 */
    auto print_byte = [](u_char* buf, int size) {
        for (int index = 1; index < size; index++)
            printf("-%02X",buf[index]);
    };
    printf("target_mac = %02X", _target_mac[0]);
    print_byte(_target_mac, ETHERNET_MAC_BYTE);

    printf(", source_mac = %02X",_source_mac[0]);
    print_byte(_source_mac, ETHERNET_MAC_BYTE);

    switch(_type)
    {
        case ETHERTYPE_IP:
            printf(" protocol = %s", "IPV4");
        case ETHERTYPE_ARP:
            printf(" protocol = %s", "ARP");
        case ETHERTYPE_REVARP:
            printf(" protocol = %s", "Reverse ARP");
        case ETHERTYPE_AT:
            printf(" protocol = %s", "AppleTalk");
        case ETHERTYPE_AARP:
            printf(" protocol = %s", "AppleTalk ARP");
        case ETHERTYPE_VLAN:
            printf(" protocol = %s", "VLAN");
        case ETHERTYPE_IPV6:
            printf(" protocol = %s", "IPV6");
        case ETHERTYPE_LOOPBACK:
            printf(" protocol = %s", "LOOPBACK"); 
    }
    printf("\n");
    return 0;
}

Ethernet::Ethernet(bool is_opposite_byte)
    : Protocol(is_opposite_byte)
    , _header(is_opposite_byte)
    , _data(nullptr)
    , _data_size(0)
{
    _size = 0;
}

Ethernet::~Ethernet()
{
    _data = nullptr;
    _data_size = 0;
}

/*
 * @remark 由于抓包程序可能在设备驱动程序未填充字节前就已捕获，故该函数不调用
 * */
bool Ethernet::check_buffer_length(void *buffer, uint32_t size)
{
    return size >= ETHER_MIN_LEN;
}

/*
 * 解析网络数据包
 * @ return ErrorCode 
 * */
int Ethernet::parse(void *buffer, uint32_t size)
{
    int error_code = _header.parse(buffer, size);
    JUDGE_RETURN(error_code != PARSE_SUCCESS, error_code);
    _data = (void*)((u_char*)buffer + _header._size);

    /* 暂时提取剩余缓冲区为数据区域长度 */
    _data_size = size - _header._size;
    _size = size;
    _is_opposite_byte ? opposite_byte() : 1;
    return PARSE_SUCCESS;
}

int Ethernet::opposite_byte()
{
    return 0;
}

int Ethernet::debug_info()
{
    _header.debug_info();
    return 0;
}

