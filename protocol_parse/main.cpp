#include "base.h"
#include "map_file.h"
#include "pcap.h"

int opposite_int_order(int value)
{
    return OPPOSIZE_BYTE_ORDER(value);
}

int order(int value) 
{
    return value;
}

int main()
{
    //char file_name[] = "/home/yang/do_wireshark/TSD/protocol_parse/day3.pcap";
    char file_name[] = "./day3.pcap"; 
    int error_code = 0;
    PcapFile pcap_file;
    error_code = pcap_file.load_file(file_name);
    if (error_code != 0)
    {
        printf("load file error: %d, %s\n",error_code, strerror(error_code));
        return -1;
    }

    error_code = pcap_file.parse();
    if (error_code != PARSE_SUCCESS)
    {
        printf("parse pcap file error: %d\n",error_code);
        return -1;
    }
    // 打印出pcap头文件的内容
    pcap_file._file_header.debug_info();
    printf("packet amout = %d\n",(int)pcap_file._packets.size());
    // 遍历vector
    for (auto value : pcap_file._packets)
    {
        value.debug_info();
    }
    return 0;
}
