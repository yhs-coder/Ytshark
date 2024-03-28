#include "ip.h"

Ip::Ip() : Protocol(false), _data(nullptr)
{
    _version = 0;
    _header_len = IP_HEADER_FIX_SIZE;
    _service_type = 0;
    _total_len = 0;
    _identification = 0;
    _flags = 0;
    _fragment_offset = 0;
    _ttl = 0;
    _protocol = 0;
    _checksum = 0;
    _source_ip = 0;
    _target_ip = 0;
    _size = 0;
    _is_opposite_byte = get_endian() == LITTLE_ENDIAN;
}

Ip::~Ip()
{
}


bool Ip::is_protocol_type()
{
    switch(_protocol)
    {
        case TRANSPORT_LAYER_PROTOCOL_ICMP:
            return true;
        case TRANSPORT_LAYER_PROTOCOL_TCP: 
            return true;
        case TRANSPORT_LAYER_PROTOCOL_UDP:
            return true;
        default:
            return false;   
    }
}

bool Ip::check_buffer_length(void *buffer, uint32_t size)
{
    return size >= IP_HEADER_FIX_SIZE;
}


int Ip::opposite_byte()
{
    return 0;
}

int Ip::parse(void *buffer, uint32_t size)
{
    // 判断操作字节数是否小于ip首部长度
    JUDGE_RETURN(!check_buffer_length(buffer, size), IP_PARSE_ERROR_LENGTH);
    u_char *data = (u_char*)buffer;
        
    /** 4byte  **/
    // 读取第一个字节，并通过位操作提取出这个字节中的高4位
    // & 0xf表示对移动后的结果进行按位与操作，目的是保留低4位，将高4位清零
    // _version大小为4bit,网络字节序，所以data[0] == _version(4bit)  _header_len(4bit)
    _version = (data[0] >> 4) & 0xf;
    JUDGE_RETURN(!IS_IP_VERSION(_version), IP_PARSE_ERROR_VERSION); 
    _header_len = (data[0] & 0xf) * 4;
    _service_type = data[1]; 
    _total_len = ntohs(*(uint16_t*)(&data[2]));
    /** 4bytes **/
    _identification = ntohs(*(uint16_t*)(&data[4]));
    _flags = (data[6] >> 5) & 0b00000111;   // 提取分片标志位
    // 0x1fff == 0001 1111 1111 1111, 网络字节序，flags在高3位，000除掉
    _fragment_offset = ntohs(*(uint16_t*)(&data[6])) & 0x1fff; // TODO:有点问题


    /** 4bytes **/
    _ttl = data[8];
    _protocol = data[9];
    _checksum = ntohs(*(uint16_t*)(&data[10]));

    /** 4bytes **/
    _source_ip = *(uint32_t*)(&data[12]);
    _target_ip = *(uint32_t*)(&data[16]);

    /**option padding **/ 
    _data = data + _header_len; 
    return 0;
}


int Ip::debug_info()
{
    auto print_address = [](uint32_t ip) {
        struct in_addr addr;
        addr.s_addr = ip;
        printf("ip = %s", inet_ntoa(addr));
    };
    printf("\tsource ");
    print_address(_source_ip);
    printf("\ttarget ");
    print_address(_target_ip);
    printf("\tttl = %d\t%s\n", _ttl, get_transport_layer_protocol_name(_protocol));
    return 0;
}
