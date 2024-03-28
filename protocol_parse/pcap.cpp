#include "pcap.h"

PcapHeader::PcapHeader() : Protocol(false)
{
    _size = PCAP_HEADER_BYTES;
}

bool PcapHeader::check_buffer_length(void *buffer, uint32_t size)
{
    // size大于pcap文件头长度
    return size <= PCAP_HEADER_BYTES;
}

int PcapHeader::parse(void *buffer, uint32_t size)
{
    JUDGE_RETURN(!this->check_buffer_length(buffer, size), PCAP_PARSE_ERROR_HEADER_LENGTH);

    u_char *pbuffer = (u_char*)buffer;
    memcpy(&(_magic), pbuffer, sizeof(_magic));
    pbuffer += sizeof(_magic);
    JUDGE_RETURN(!IS_PCAP_MAGIC_VALUE(_magic), PCAP_PARSE_ERROR_HEADER_LENGTH);

    memcpy(&(_major), pbuffer, sizeof(_major));
    pbuffer += sizeof(_major);
    memcpy(&(_minor), pbuffer, sizeof(_minor));
    pbuffer += sizeof(_minor);
    memcpy(&(_this_zone), pbuffer, sizeof(_this_zone));
    pbuffer += sizeof(_this_zone);
    memcpy(&(_sig_flags), pbuffer, sizeof(_sig_flags));
    pbuffer += sizeof(_sig_flags);
    memcpy(&(_snap_len), pbuffer, sizeof(_snap_len));
    pbuffer += sizeof(_snap_len);
    memcpy(&(_link_type), pbuffer, sizeof(_link_type));
    pbuffer += sizeof(_link_type);

    opposite_byte();
    return PARSE_SUCCESS;
}

int PcapHeader::debug_info()
{
    printf("-------------------------------------------------\n");
    printf("大小端标识 = %X\n", _magic);
    printf("主要版本号 = %X\n", _major);
    printf("次要版本号 = %X\n", _minor);
    printf("当地标准时间 = %d\n", _this_zone);
    printf("时间戳精度 = %d\n", _sig_flags);
    printf("数据包最大长度 = %d\n",_snap_len);
    printf("链路类型 = %X\n", _link_type);
    printf("-------------------------------------------------\n");
    return 0;
}

int PcapHeader::opposite_byte()
{
    // 如果是小端模式
    if (IS_PCAP_OPPOSITE_BYTE(_magic))
    {
        // 转换字节序
        _is_opposite_byte = true;
        _major = OPPOSIZE_SHORT_ORDER(_major);
        _minor = OPPOSIZE_SHORT_ORDER(_minor);
        _this_zone = OPPOSIZE_BYTE_ORDER(_this_zone);
        _sig_flags = OPPOSIZE_BYTE_ORDER(_sig_flags);
        _snap_len = OPPOSIZE_BYTE_ORDER(_snap_len);
        _link_type = OPPOSIZE_BYTE_ORDER(_link_type);
    }
    return 0;
}

PcapPacketHeader::PcapPacketHeader(bool is_opposite_byte) : Protocol(is_opposite_byte)
{
    _size = PCAP_PACKET_HEADER_BYTES;
}

bool PcapPacketHeader::check_buffer_length(void *buffer, uint32_t size)
{
    return size <= (int)PCAP_PACKET_HEADER_BYTES;
}

/*
 * 解析pcap数据包头部
 * @return ErrorCode
 * */
int PcapPacketHeader::parse(void *buffer, uint32_t size)
{
    JUDGE_RETURN(!check_buffer_length(buffer, size), PCAP_PARSE_ERROR_HEADER_LENGTH);

    u_char *pbuffer = (u_char*)buffer;
    memcpy(&(_timestamp_s), pbuffer, sizeof(_timestamp_s));
    pbuffer += sizeof(_timestamp_s);
    memcpy(&(_timestamp_ms), pbuffer, sizeof(_timestamp_ms));
    pbuffer += sizeof(_timestamp_ms);
    memcpy(&(_caplen), pbuffer, sizeof(_caplen));
    pbuffer += sizeof(_caplen);
    memcpy(&(_len), pbuffer, sizeof(_len));
    pbuffer += sizeof(_len);
    
    _is_opposite_byte ? opposite_byte(): 1;
    return PARSE_SUCCESS;
}

int PcapPacketHeader::opposite_byte()
{

    _timestamp_s = OPPOSIZE_BYTE_ORDER(_timestamp_s);
    _timestamp_ms = OPPOSIZE_BYTE_ORDER(_timestamp_ms);
    _caplen = OPPOSIZE_BYTE_ORDER(_caplen);
    _len = OPPOSIZE_BYTE_ORDER(_len);
    return 0;
}

int PcapPacketHeader::debug_info()
{
    // timestamp_ms时间戳的单位是微秒（microseconds）, 1 秒等于 1000000 微秒
    time_t time_stamp = _timestamp_s + _timestamp_ms /1000000;

    // 将时间戳（秒数表示的时间）转换为本地时间，并返回一个指向 struct tm 结构体的指针。
    tm *tm = localtime(&time_stamp);
    char buffer[MAX_FILE_PATH]; // 存储格式化后的时间字符串
    if (tm)
    {
        // 将时间信息按照指定的格式转换成字符串
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm);
    }
    else 
    {
        sprintf(buffer, "unknown timestamp_s = %d, timestamp_ms = %d\n",_timestamp_s,_timestamp_ms);
    }
    printf("[%s.%d]\t%dB\t",buffer,_timestamp_ms, _caplen);
    return 0;
}

PcapPacket::PcapPacket(bool is_opposite_byte) 
    : header(is_opposite_byte)
    , ethernet()
{}

int PcapPacket::debug_info()
{   
    header.debug_info();
    ethernet.debug_info();
    return 0;
}

PcapFile::PcapFile()
    : _file_header()
    , _packets()
    , _map_file()
{}

PcapFile::~PcapFile()
{}

//void *PcapFile::fun_get_value(uint32_t value)
//{
//    return nullptr;
//}

/*
 * 是否加载了文件
 * @return bool 
 * */
bool PcapFile::is_load_file()
{
    return _map_file._map_addr != nullptr;
}

/*
 * 打开并映射文件
 * @return errno 
 * */
int PcapFile::load_file(const char *file_path)
{ 
    int open_mode = O_RDWR;
    int protect_mode = PROT_READ | PROT_WRITE;
    int flags = MAP_SHARED;
    if (_map_file.open_file(file_path, open_mode) != 0)
        return errno;

    //printf("_file_size:%d\n",_map_file._file_size);
    if (_map_file.mmap_file(protect_mode, flags) != 0)
        return errno;

    return 0;
}


/*
 * 解析pcpa文件
 * @return bool 
 * */
int PcapFile::parse()
{
    if (!is_load_file())
        return PCAP_PARSE_ERROR_LOAD_FILE;
    uint32_t offset = 0;
    int error_code = 0; 
    /* 解析pcap header(pcap文件头)*/
    void *pcap_header_start = _map_file.get_buffer(offset, PCAP_HEADER_BYTES);
    if (pcap_header_start == nullptr)
        return PCAP_PARSE_ERROR_MAP_GET_BUFFER;
    error_code = _file_header.parse(pcap_header_start, PCAP_HEADER_BYTES);
    JUDGE_RETURN(error_code != PARSE_SUCCESS, error_code);
    // 遍历pcap文件，循环解析数据包
    for (offset = PCAP_HEADER_BYTES; offset < _map_file._file_size;)
    {
        // 将映射的地址移动到Packet Header 
        u_char *packet_header_start = (u_char*)_map_file.get_buffer(offset, PCAP_PACKET_HEADER_BYTES);
        if (packet_header_start == nullptr)  
            return PCAP_PARSE_ERROR_MAP_GET_BUFFER;
        
        PcapPacket packet(_file_header._is_opposite_byte);
        // 解析数据包头 Packet Header
        error_code = packet.header.parse(packet_header_start, PCAP_PACKET_HEADER_BYTES);
        JUDGE_RETURN(error_code != PARSE_SUCCESS, error_code);
        
        
        // 偏移量增加数据包头的长度 16字节
        offset += PCAP_PACKET_HEADER_BYTES;
        
        u_char *packet_data_start = (u_char*)_map_file.get_buffer(offset, packet.header._caplen);
        if (packet_data_start == nullptr)
            return PCAP_PARSE_ERROR_MAP_GET_BUFFER;
       
        // 解析Packet Data，即数据包中的数据
        // 移动offset字节，指向数据包中数据域的起始地址
        error_code = packet.ethernet.parse(packet_data_start, packet.header._caplen);
        JUDGE_RETURN(error_code != PARSE_SUCCESS, error_code);
      
        //偏移量增加caplen，使其指针指向下一个数据包的包头
        offset += packet.header._caplen;
        // 将数据包(即数据包头和数据)的信息插入vector中，后面遍历输出
        _packets.push_back(packet); 
    }
    return (offset == _map_file._file_size ? PARSE_SUCCESS : PCAP_PARSE_ERROR_PACKET_HEADER_LENGTH);
}



