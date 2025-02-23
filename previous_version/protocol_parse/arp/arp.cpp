#include "arp.h"

ArpMacAndIp::ArpMacAndIp() : Protocol(false)
{
    _is_opposite_byte = get_endian() == LITTLE_ENDIAN;
}

ArpMacAndIp::~ArpMacAndIp()
{
}


const std::type_info &ArpMacAndIp::get_class_type_info()
{
    return typeid(*this);
}

bool ArpMacAndIp::check_buffer_length(void *buffer, uint32_t size)
{
    // size大于大于arp报文内容
    return size >= ARP_DATA_SIZE(MAC_COMMON_SIZE, IP_COMMON_SIZE);
}
int ArpMacAndIp::parse(void *buffer, uint32_t size)
{
    // 检查size是否有效
    JUDGE_RETURN(!check_buffer_length(buffer, size), ARP_PARSE_ERROR_DATA_LENGTH);

    u_char *data = (u_char*)buffer;
    memcpy(&(_source_mac), data, MAC_COMMON_SIZE );
    data += MAC_COMMON_SIZE;
    memcpy(&(_source_ip), data, IP_COMMON_SIZE );
    data += IP_COMMON_SIZE;
    memcpy(&(_target_mac), data, MAC_COMMON_SIZE );
    data += MAC_COMMON_SIZE;
    memcpy(&(_target_ip), data, IP_COMMON_SIZE );
    data += IP_COMMON_SIZE;
    _is_opposite_byte ? opposite_byte() : 1;
    return PARSE_SUCCESS;
}

int ArpMacAndIp::opposite_byte()
{
    _source_ip = OPPOSIZE_BYTE_ORDER(_source_ip);
    _target_ip = OPPOSIZE_BYTE_ORDER(_target_ip);
    return 0;
}

int ArpMacAndIp::debug_info()
{
    return 0;
}

Arp::Arp() : Protocol(false), _data(nullptr)
{
    _is_opposite_byte = get_endian() == LITTLE_ENDIAN;
}

Arp::~Arp()
{
    if (_data != nullptr)
    {
        delete _data;
        _data = nullptr;
    }
}
const std::type_info &Arp::get_class_type_info()
{
    return typeid(*this);
}

bool Arp::is_hardware_type()
{
    switch(_hardware_type)
    {
        case ARPHRD_ETHER:
            return true;
        default:
            return false;
    }
}

bool Arp::is_operation_type()
{
    /* ARP protocol opcodes. */
    switch (_op_type)
    {
        case ARPOP_REQUEST:
            return true;
        case ARPOP_REPLY:
            return true;
        case ARPOP_RREQUEST:
            return true;
        case ARPOP_RREPLY:
            return true;
        case ARPOP_NAK:
            return true;
        default:
            return false;
    }
}

bool Arp::is_protocol_type()
{
    switch (_protocol_type)
    {
        case ETHERTYPE_IP:
            return true;
        default:
            return true;
    }
}

bool Arp::check_total_size(uint32_t size)
{
    return size >= ARP_TOTAL_SIZE(_hardware_size, _protocol_size);
}

Protocol * Arp::new_arp_data_class()
{
    if (_hardware_type == ARPHRD_ETHER && _protocol_type == ETHERTYPE_IP)
        return new ArpMacAndIp();
    return nullptr;
}

const char *Arp::get_arp_operation_name(uint32_t type)
{
    switch(type)
    {
        case ARPOP_REQUEST:
            return "arp请求";
        case ARPOP_REPLY:
            return "arp应答";
        case ARPOP_RREQUEST:
            return "rarp请求";
        case ARPOP_RREPLY:
            return "rarp应答";
        case ARPOP_NAK:
            return "atm_arp nak";
        default:
            return "unknown";
    }
}

bool Arp::check_buffer_length(void *buffer, uint32_t size)
{
    return size >= ARP_HEADER_SIZE;
}


int Arp::parse(void *buffer, uint32_t size)
{
    JUDGE_RETURN(!check_buffer_length(buffer, size), ARP_PARSE_ERROR_HEADER_LENGTH);
    u_char *data = (u_char *)buffer;
    memcpy(&(_hardware_type), data, sizeof(_hardware_type));
    data += sizeof(_hardware_type);
    memcpy(&(_protocol_type), data, sizeof(_protocol_type));
    data += sizeof(_protocol_type);
    _hardware_size = *data++;
    _protocol_size = *data++;
    memcpy(&(_op_type), data, sizeof(_op_type));
    data += sizeof(_op_type);
    _is_opposite_byte ? opposite_byte() : 1;
    JUDGE_RETURN(!check_total_size(size), ARP_PARSE_ERROR_DATA_LENGTH);
    _data =new_arp_data_class();
    if (_data != nullptr)
        return _data->parse(data, size - ARP_HEADER_SIZE);
    return PARSE_SUCCESS;
}

int Arp::opposite_byte()
{
    _hardware_type = OPPOSIZE_SHORT_ORDER(_hardware_type);
    _protocol_type = OPPOSIZE_SHORT_ORDER(_protocol_type);
    _op_type = OPPOSIZE_SHORT_ORDER(_op_type);
    return 0;
}

int Arp::debug_info()
{
    auto print_byte = [](uint8_t* buf, int size) {
        for (int index = 1; index < size; index++)
            printf("-%02X",buf[index]);
    };
    if (_data != nullptr && _data->get_class_type_info() == typeid(ArpMacAndIp))
    {
        printf("[%s] ", Arp::get_arp_operation_name(_op_type));
        ArpMacAndIp *data = (ArpMacAndIp*)_data;
        printf("source: %d.%d.%d.%d(", IP_GETTER_RIRST(data->_source_ip), 
                IP_GETTER_SECOND(data->_source_ip),
                IP_GETTER_THIRD(data->_source_ip),
                IP_GETTER_FOURTH(data->_source_ip));
        printf("%02X", data->_source_mac[0]);
        print_byte(data->_source_mac, MAC_COMMON_SIZE);
        printf(")  target: %d.%d.%d.%d(", IP_GETTER_RIRST(data->_target_ip), 
                IP_GETTER_SECOND(data->_target_ip),
                IP_GETTER_THIRD(data->_target_ip),
                IP_GETTER_FOURTH(data->_target_ip));
        printf("%02X", data->_target_mac[0]);
        print_byte(data->_target_mac, MAC_COMMON_SIZE);
        printf(")\n");
    }
    else 
    {
        printf("[%s]\n",Arp::get_arp_operation_name(_op_type));
    }
}
