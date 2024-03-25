#include "pcap.h"

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
    
    /* pcap header(pcap文件头)*/
    uint32_t *pcap_header_start = (uint32_t*)_map_file.get_buffer(offset, PCAP_HEADER_BYTES);
    if (pcap_header_start == nullptr)
        return PCAP_PARSE_ERROR_HEADER;

    _file_header.magic = pcap_header_start[0];
    // 检查pcap文件头的magic值
    if (!IS_PCAP_MAGIC_VALUE(_file_header.magic))
        return PCAP_PARSE_ERROR_MAGIC;
    
    _file_header.major = ((uint16_t*)pcap_header_start)[2];
    _file_header.minor = ((uint16_t*)pcap_header_start)[3];
    _file_header.this_zone = pcap_header_start[2];
    _file_header.sig_flags = pcap_header_start[3];
    _file_header.snap_len = pcap_header_start[4];
    _file_header.link_type = pcap_header_start[5];
    _file_header.opposite_byte_order();
    
    // 遍历pcap文件，循环解析数据包
    for (offset = PCAP_HEADER_BYTES; offset < _map_file._file_size;)
    {
        // 将映射的地址移动到Packet Header 
        uint32_t *packet_header_start = (uint32_t*)_map_file.get_buffer(offset, PCAP_PACKET_HEADER_BYTES);
        if (packet_header_start == nullptr)  break;
        
        PcapPacket packet;
        // 解析数据包头 Packet Header
        packet.header.timestamp_s = packet_header_start[0];
        packet.header.timestamp_ms = packet_header_start[1];
        packet.header.caplen = packet_header_start[2];
        packet.header.len = packet_header_start[3];
        if (_file_header.magic == PCAP_MAGIC_OPPOSITE_MODE)
            // 将小端字节序进行转换
            packet.header.opposite_byte_order();

        // 偏移量增加数据包头的长度 16字节
        offset += PCAP_PACKET_HEADER_BYTES;
        
        // 解析Packet Data，即数据包中的数据
        // 移动offset字节，指向数据包中数据域的起始地址
        void *packet_data_start = (void*)_map_file.get_buffer(offset, packet.header.caplen);
        if (packet_data_start == nullptr)
            return PCAP_PARSE_ERROR_PACKET_DATA;

        // 保存数据域的起始地址
        packet.packet_data = packet_data_start; 
        // 将数据包(即数据包头和数据)的信息插入vector中，后面遍历输出
        _packets.push_back(packet); 
        
        //偏移量增加caplen，使其指针指向下一个数据包的包头
        offset += packet.header.caplen;
    }
    
    return (offset == _map_file._file_size ? PCAP_PARSE_SUCCESS : PCAP_PARSE_ERROR_PACKET_HEADER);
}

void PcapHeader::pcap_header_info()
{
    printf("-------------------------------------------------\n");
    printf("大小端标识 = %X\n", magic);
    printf("主要版本号 = %X\n", major);
    printf("次要版本号 = %X\n", minor);
    printf("当地标准时间 = %d\n", this->this_zone);
    printf("时间戳精度 = %d\n", sig_flags);
    printf("数据包最大长度 = %d\n",snap_len);
    printf("链路类型 = %X\n", link_type);
    printf("-------------------------------------------------\n");
}

void PcapHeader::opposite_byte_order()
{
    // 主机字节序，即小端模式
    if (magic == PCAP_MAGIC_OPPOSITE_MODE)
    {
        // 转换字节序
        major = OPPOSIZE_BYTE_ORDER(major);
        minor = OPPOSIZE_BYTE_ORDER(minor);
        this_zone = OPPOSIZE_BYTE_ORDER(this_zone);
        sig_flags = OPPOSIZE_BYTE_ORDER(sig_flags);
        snap_len = OPPOSIZE_BYTE_ORDER(snap_len);
        link_type = OPPOSIZE_BYTE_ORDER(link_type);
    }
}


void PacketHeader::pcap_packet_header_info()
{
    // 时间戳的单位可能是微秒（microseconds）, 1 秒等于 1000000 微秒
    time_t time_stamp = timestamp_s + timestamp_ms /1000000;

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
        sprintf(buffer, "unknown timestamp_s = %d, timestamp_ms = %d\n",timestamp_s,timestamp_ms);
    }
    printf("[%s.%d] %dB\n",buffer,timestamp_ms, caplen);
}

void PacketHeader::opposite_byte_order()
{
    timestamp_s = OPPOSIZE_BYTE_ORDER(timestamp_s);
    timestamp_ms = OPPOSIZE_BYTE_ORDER(timestamp_ms);
    caplen = OPPOSIZE_BYTE_ORDER(caplen);
    len = OPPOSIZE_BYTE_ORDER(len);
}





