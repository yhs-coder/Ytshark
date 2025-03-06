#ifndef TSHARK_DATATYPE_H
#define TSHARK_DATATYPE_H
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

struct Packet {
	int frame_number;			// ���ݰ����
	std::string time;			// ���ݰ���ʱ���
	std::string src_mac;		// Դmac��ַ
	std::string dst_mac;		// Ŀ��mac��ַ
	uint32_t cap_len;			// ʵ�ʲ������ݰ��ĳ���
	uint32_t len;				// ���ݰ��������еĳ���
	std::string src_ip;			// ԴIP��ַ
	std::string src_location;	// Դip������
	uint16_t src_port;			// Դ�˿�
	std::string dst_ip;			// Ŀ��IP��ַ
	std::string dst_location;	// Ŀ��ip������
	uint16_t dst_port;			// Ŀ�Ķ˿�
	std::string protocol;		// Э��
	std::string info;			// ���ݰ��ĸ�Ҫ��Ϣ
	uint32_t file_offset;		// ��PACP�ļ��е�ƫ����
};

// PCAPȫ���ļ�ͷ
struct PcapHeader {
	uint32_t magic_number;      // �ļ���ʽ (0xa1b2c3d4Ϊ��ˣ�0xd4c3b2a1ΪС��)
	uint16_t version_major;     // pcap�ļ��汾��
	uint16_t version_minor;     // �ΰ汾��
	uint32_t thiszone;			// ʱ��ƫ��
	uint32_t sigfigs;			// ʱ�������
	uint32_t snaplen;			// �������ݰ�����
	uint32_t network;			// ��·������
};


// ÿ�����ݱ���ͷ
struct PacketHeader {
	uint32_t ts_sec;		// ʱ������룩
	uint32_t ts_usec;		// ʱ�����΢�룩
	uint32_t caplen;		// ʵ�ʲ������ݰ�����
	uint32_t len;			// ���ݰ�ԭʼ����
};

// ������Ϣ
struct AdapterInfo {
	// 1. \Device\NPF_{4978D6C4-D00F-4FFF-AABE-F4A24A422538} (��������* 10)
	int id;					// �������
	std::string name;		// �м������,�豸��Ψһ��ʶ�������ڱ�ʶ����ӿ�/����
	std::string remark;		// ������������ƣ�������������
};
#endif