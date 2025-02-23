#include "ethernet.h"
#include "ip.h"
#include "arp.h"

//Ethernet::Ethernet() : Protocol(false), _data(nullptr)
Ethernet::Ethernet() : Protocol(false), _data()
{
    memset(_preamble, ETHERNET_PREAMBLE_VALUE,ETHERNET_PREAMBLE_BYTE);
    _sfd = ETHERNET_SFD_VALUE;
    memset(_target_mac, 0 , ETHERNET_MAC_BYTE);
    memset(_source_mac, 0 , ETHERNET_MAC_BYTE);
    _type = 0;
    _size = ETHERNET_HEADER_MIN_BYTE;
    _is_opposite_byte = get_endian() == LITTLE_ENDIAN;
}

Ethernet::~Ethernet()
{
   // if (_data != nullptr)
   // {
   //     printf("~Ethernet.......\n");
   //     delete _data;
   //     _data = nullptr;
   // }
}

/*
 * @以buffer起始地址作为以太网数据包头，检查受否有前导码和帧开始符
 * @return bool 
 * */
bool Ethernet::is_have_preamble_and_sfd(void *buffer, uint32_t size)
{
    // 以太网帧不包含前导码和帧开始符这些物理层的内容
    // 数据区域是以太网帧的有效载荷部分开始，也就是DST目标MAC地址开始
    // 所以以下函数无任何意义！！！！！！！！！！！！！！！！！！！！！！！！
    if (size < ETHERNET_PREAMBLE_BYTE + ETHERNET_SFD_BYTE)
        return false;
   // u_char *cbuffer = (u_char*)buffer;
    //printf("ethernet.cpp line:%d\n",__LINE__);
    return false;
    //return (memcmp(cbuffer, _preamble, ETHERNET_PREAMBLE_BYTE) == 0) && (*(cbuffer + ETHERNET_PREAMBLE_BYTE) == _sfd);
}

bool Ethernet::is_protocol_type()
{
    switch(_type)
    {
        // 类型定义在/usr/include/net/ethernet.h文件中
        case ETHERTYPE_IP:
            return true;
        case ETHERTYPE_ARP:
            return true;
        case ETHERTYPE_REVARP:
        case ETHERTYPE_VLAN:
        case ETHERTYPE_IPV6:
        case ETHERTYPE_LOOPBACK:
            return true;
        default:
            return false;
    }
}

bool Ethernet::check_buffer_length(void *buffer, uint32_t size)
{
    if (is_have_preamble_and_sfd(buffer, size))
        return size <= ETHERNET_HEADER_MAX_BYTE;
    return size >= ETHERNET_HEADER_MIN_BYTE;
}

int Ethernet::parse(void *buffer, uint32_t size)
{
    JUDGE_RETURN(!check_buffer_length(buffer, size), ETHERNET_PARSE_ERROR_MIN_LENGTH);

    u_char *skip_buffer = (u_char*)buffer;
    /*********************************************************************************************************
     * 以太网帧不包含前导码和帧开始符这些物理层的内容
     * 数据区域是以太网帧的有效载荷部分开始，也就是DST目标MAC地址开始
     * 所以以下处理无任何意义！！！！！！！！！！！！！！！！！！！！！！！！
     * *****************************************************************************************************/ 
    //if (is_have_preamble_and_sfd(buffer, size))
    //{
    //    // 指针挪动（前导值+SFD）个字节，指向DST字段
    //    skip_buffer += ETHERNET_PREAMBLE_BYTE + ETHERNET_SFD_BYTE;
    //    _size = ETHERNET_HEADER_MAX_BYTE;
    //}

    memcpy(&(_target_mac), skip_buffer, ETHERNET_MAC_BYTE); 
    // 移动skip_buffer,指向SRC字段
    skip_buffer += ETHERNET_MAC_BYTE;
    memcpy(&(_source_mac), skip_buffer, ETHERNET_MAC_BYTE); 
    skip_buffer += ETHERNET_MAC_BYTE;
    memcpy(&(_type), skip_buffer, sizeof(_type));
    skip_buffer += sizeof(_type);
    // 因为以太网数据包的字节序为网络字节序
    // _type整数字节序 与 ethernet.h定义的协议号类型相反
    // 需要反转字节序
    //_type = OPPOSIZE_SHORT_ORDER(_type);

    _is_opposite_byte ? opposite_byte() : 1;
    //return is_protocol_type() ? PARSE_SUCCESS : ETHERNET_PARSE_ERROR_PROTOCOL_TYPE;
    
    int error_code = PARSE_SUCCESS;
    switch(_type)
    {
        case ETHERTYPE_IP:
            //error_code = _data.parse(skip_buffer, size - (skip_buffer - (u_char*)buffer));
            
            //printf("尝试输出ip数据包信息：\n");
            //_data.debug_info();
            //sleep(2);
            /************************************************************************************************/
            // _data是Protocol类（虚基类），使其指针指向Ip对象，后续_data的实际对象是Ip类
            _data = new Ip();
            if (_data != nullptr)
            {
                error_code = _data->parse(skip_buffer, size - (skip_buffer - (u_char*)buffer));
            //    printf("尝试输出ip数据包信息：\n");
            //    _data->debug_info();
            //    sleep(2);
            }
            break;
        case ETHERTYPE_ARP:
            _data = new Arp();
            if (_data != nullptr)
            {
                error_code = _data->parse(skip_buffer, size - (skip_buffer - (u_char*)buffer));
            }
            break;
        case ETHERTYPE_REVARP:
        case ETHERTYPE_VLAN:
        case ETHERTYPE_IPV6:
        case ETHERTYPE_LOOPBACK:
            break;
        default:
            break;
    }
    return error_code;
}

int Ethernet::opposite_byte()
{
    // 需要和ethernet.h定义协议类型作比较，需要把小端字节序转换
    // 比如和0x0800比较 
    _type = OPPOSIZE_SHORT_ORDER(_type);
    return 0;
}

int Ethernet::debug_info()
{
    /* 默认不输出前导符和帧开始符 */
    auto print_byte = [](u_char* buf, int size) {
        for (int index = 1; index < size; index++)
            printf("-%02X",buf[index]);
    };
    printf(", source_mac = %02X",_source_mac[0]);
    print_byte(_source_mac, ETHERNET_MAC_BYTE);
    printf("target_mac = %02X", _target_mac[0]);
    print_byte(_target_mac, ETHERNET_MAC_BYTE);

    
    printf("   %s", get_network_layer_protocol_name(_type));
    //sleep(1); 
    // 输出传输层协议内容
    //_data.debug_info();
    if (_data != nullptr)
    {
    //    printf("打印IP数据包之前\n");
    //    sleep(10);
        _data->debug_info();
    }
    else 
        printf("\n");
    return 0;
}


