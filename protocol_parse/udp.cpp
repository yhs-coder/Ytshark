#include "udp.h"

Udp::Udp() : Protocol(false)
{
    _is_opposite_byte = get_endian() == LITTLE_ENDIAN;
}

Udp::~Udp()
{
    //if (_data !=nullptr)
    //{
    //    delete _data;
    //    _data = nullptr;
    //}
}

bool Udp::check_total_size(uint32_t size)
{
    return size >= _total_size; 
}

const std::type_info &Udp::get_class_type_info()
{
    return typeid(*this);
}

bool Udp::check_buffer_length(void *buffer, uint32_t size)
{
    return size >= UDP_HEADER_SIZE;
}

int Udp::parse(void *buffer, uint32_t size)
{
    JUDGE_RETURN(!check_buffer_length(buffer, size), UDP_PARSE_ERROR_HEADER_LENGTH);
    u_char *data = (u_char*)buffer;
    printf("source port: %u\n", ntohs(*((uint16_t*)(&data[0]))) );
    _source_port = ntohs((*((uint16_t*)(&data[0]))));
    _target_port = ntohs(*((uint16_t*)(&data[2])));
    _total_size = ntohs((*((uint16_t*)(&data[4]))));
    _check_sum = ntohs((*((uint16_t*)(&data[6]))));
    
    _is_opposite_byte ? opposite_byte() : 1;
    printf("_is_opposite_byte = %d\n", _is_opposite_byte);
    printf("_source_port = %u, _target_port = %u, _total_size = %u _check_sum = %u\n",_source_port, _target_port, _total_size, _check_sum);
    printf("size = %d  _total_size = %d\n", size, _total_size);
    JUDGE_RETURN(!check_total_size(size), UDP_PARSE_ERROR_DATA_LENGTH);
    return PARSE_SUCCESS;
}

int Udp::opposite_byte()
{
    //OPPOSIZE_SHORT_ORDER(_source_port);
    //OPPOSIZE_SHORT_ORDER(_target_port);
    //OPPOSIZE_SHORT_ORDER(_total_size);
    //OPPOSIZE_SHORT_ORDER(_check_sum);
    return 0;
}

int Udp::debug_info()
{
    printf("  source port: %d, target port: %d, udp size:%d\n", _source_port, _target_port, _total_size);
    return 0;
}

