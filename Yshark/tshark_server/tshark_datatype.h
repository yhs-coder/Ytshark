#ifndef TSHARK_DATATYPE_H
#define TSHARK_DATATYPE_H
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

struct Packet {
	int frame_number;			// 数据包编号
	std::string time;			// 数据包的时间戳
	std::string src_mac;		// 源mac地址
	std::string dst_mac;		// 目的mac地址
	uint32_t cap_len;			// 实际捕获数据包的长度
	uint32_t len;				// 数据包在网络中的长度
	std::string src_ip;			// 源IP地址
	std::string src_location;	// 源ip归属地
	uint16_t src_port;			// 源端口
	std::string dst_ip;			// 目的IP地址
	std::string dst_location;	// 目的ip归属地
	uint16_t dst_port;			// 目的端口
	std::string protocol;		// 协议
	std::string info;			// 数据包的概要信息
	uint32_t file_offset;		// 在PACP文件中的偏移量
};

// PCAP全局文件头
struct PcapHeader {
	uint32_t magic_number;      // 文件格式 (0xa1b2c3d4为大端，0xd4c3b2a1为小端)
	uint16_t version_major;     // pcap文件版本号
	uint16_t version_minor;     // 次版本号
	uint32_t thiszone;			// 时间偏移
	uint32_t sigfigs;			// 时间戳精度
	uint32_t snaplen;			// 捕获数据包长度
	uint32_t network;			// 链路层类型
};


// 每个数据报文头
struct PacketHeader {
	uint32_t ts_sec;		// 时间戳（秒）
	uint32_t ts_usec;		// 时间戳（微秒）
	uint32_t caplen;		// 实际捕获数据包长度
	uint32_t len;			// 数据包原始长度
};

// 网卡信息
struct AdapterInfo {
	// 1. \Device\NPF_{4978D6C4-D00F-4FFF-AABE-F4A24A422538} (本地连接* 10)
	int id;					// 网卡编号
	std::string name;		// 中间的名称,设备的唯一标识符，用于标识网络接口/网卡
	std::string remark;		// 括号里面的名称，网卡描述名称
};
#endif