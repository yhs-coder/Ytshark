#include <iostream>
#include <fstream>
#include <cstdio>
#include <vector>
#include <string>
#include <sstream>
#include <Windows.h>

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

#include "ip2region_util.h"
#include "utf8_to_ansi.h"

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



struct Packet {
	int frame_number;			// ���ݰ����
	std::string time;			// ���ݰ���ʱ���
	std::string src_ip;			// ԴIP��ַ
	std::string src_location;	// Դip������
	size_t src_port;			// Դ�˿�
	std::string dst_ip;			// Ŀ��IP��ַ
	std::string dst_location;	// Ŀ��ip������
	size_t dst_port;			// Ŀ�Ķ˿�
	std::string protocol;		// Э��
	std::string info;			// ���ݰ��ĸ�Ҫ��Ϣ
	uint32_t file_offset;		// ��PACP�ļ��е�ƫ����
	uint32_t cap_len;			// �������ݰ��ĳ���
};

bool parse_line(std::string line, Packet& packet) {
	line = UTF8TOANSIString(line);

	if (line.back() == '\n') {
		line.pop_back();
	}

	std::stringstream ss(line);
	std::string field;
	std::vector<std::string> fields;
	//while (std::getline(ss, field, '\t')) {  // �����ֶ��� tab �ָ�
	//	fields.push_back(field);
	//}
	size_t start = 0, end;
	while ((end = line.find('\t', start)) != std::string::npos) {
		fields.push_back(line.substr(start, end - start));
		start = end + 1;
	}
	fields.push_back(line.substr(start));	// ������һ���Ӵ�

	// �ֶ�˳�� -e frame.number -e frame.time -e frame.cap_len -e ip.src  -e ipv6.src -e ip.dst -e ipv6.dst \
				-e tcp.srcport -e udp.srcport -e tcp.dstport  -e udp.dstport -e _ws.col.Protocol -e _ws.col.info
	// 0: frame.number
	// 1: frame.time
	// 2: frame.cap_len
	// 3: ip.src
	// 4: ipv6.src
	// 5: ip.dst
	// 6: ipv6.dst
	// 7: tcp.srcport
	// 8: udp.srcport
	// 9: tcp.dstport
	// 10: udp.dstport
	// 11: _ws.col.Protocol
	// 12: _ws.col.Info

	if (fields.size() >= 13) {
		packet.frame_number = std::stoi(fields[0]);
		packet.time = fields[1];
		packet.cap_len = std::stoi(fields[2]);
		packet.src_ip = fields[3].empty() ? fields[4] : fields[3];
		packet.dst_ip = fields[5].empty() ? fields[6] : fields[5];
		if (!fields[7].empty() || !fields[8].empty()) {
			packet.src_port = std::stoi(fields[7].empty() ? fields[8] : fields[7]);
		}
		if (!fields[9].empty() || !fields[10].empty()) {
			packet.dst_port = std::stoi(fields[9].empty() ? fields[10] : fields[9]);
		}
		packet.protocol = fields[11];
		packet.info = fields[12];
		return true;
	}
	else {
		printf("parse_line error!\n");
		return false;
	}

}

void PrintPacket(const Packet& packet) {
	// ����JSON����
	rapidjson::Document pkt_obj;
	rapidjson::Document::AllocatorType& allocator = pkt_obj.GetAllocator();

	// ����JSONΪObject��������
	pkt_obj.SetObject();

	// ���JSON�ֶ�
	pkt_obj.AddMember("frame_number", packet.frame_number, allocator);
	pkt_obj.AddMember("timestamp", rapidjson::Value(packet.time.c_str(), allocator), allocator);
	pkt_obj.AddMember("src_ip", rapidjson::Value(packet.src_ip.c_str(), allocator), allocator);
	pkt_obj.AddMember("src_location", rapidjson::Value(packet.src_location.c_str(), allocator), allocator);
	pkt_obj.AddMember("src_port", packet.src_port, allocator);
	pkt_obj.AddMember("dst_ip", rapidjson::Value(packet.dst_ip.c_str(), allocator), allocator);
	pkt_obj.AddMember("dst_location", rapidjson::Value(packet.dst_location.c_str(), allocator), allocator);
	pkt_obj.AddMember("dst_port", packet.dst_port, allocator);
	pkt_obj.AddMember("protocol", rapidjson::Value(packet.protocol.c_str(), allocator), allocator);
	pkt_obj.AddMember("info", rapidjson::Value(packet.info.c_str(), allocator), allocator);
	pkt_obj.AddMember("file_offset", packet.file_offset, allocator);
	pkt_obj.AddMember("cap_len", packet.cap_len, allocator);


	// ���л�ΪJSON�ַ���
	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	pkt_obj.Accept(writer);

	// ��ӡJSON���
	std::cout << buffer.GetString() << std::endl;
}


void ParsePacpFile() {
	std::string packet_file = R"(D:\code\C++\EasyTshark\packets.pcap)";
	std::ifstream file(packet_file.c_str(), std::ios::binary);
	if (!file) {
		std::cerr << "Failed to open file." << std::endl;
		return;
	}

	// ��ȡpcap�ļ�ͷ
	PcapHeader pcap_header;
	file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapHeader));

	// ѭ����ȡÿһ�����ݱ���
	while (file) {
		// �ȶ�ȡ��һ�����ĵ�ͷ
		PacketHeader packet_header;
		file.read(reinterpret_cast<char*>(&packet_header), sizeof(PacketHeader));
		if (!file) break;
		// �ȼ���
		// if (file.fail() || file.bad()) break;

		// ��ȡ��һ�����ĵ�����
		std::vector<unsigned char> data(packet_header.caplen);
		file.read(reinterpret_cast<char*>(data.data()), packet_header.caplen);

		printf("���ݰ�[ʱ��: %d  ����: %d]: ", packet_header.ts_sec, packet_header.caplen);
		for (auto byte : data) {
			printf("%02X ", byte);
		}
		std::cout << "\n";
	}
	file.close();

}

bool read_packet_hex(const std::string& file_path, uint32_t offset, uint32_t length, std::vector<unsigned char>& buffer) {
	std::ifstream file(file_path, std::ios::binary);
	if (!file) {
		std::cerr << "Failed to open file." << std::endl;
		return false;
	}

	// ÿ���ƶ���pcap�ļ���ʼλ�ã��ƶ�offset�����ı�������λ��
	file.seekg(offset, std::fstream::beg);
	// ȷ��read���ж�ȡʱ����������С�㹻
	buffer.resize(length);
	file.read(reinterpret_cast<char*>(buffer.data()), length);

	// ������ƶ����ļ���ʼ
	//file.seekg(0, std::fstream::beg);

	file.close();
	return true;
}

int main()
{
	std::string exe_path = R"(D:\setup\Wireshark\tshark)";
	std::string packet_file = R"(D:\code\C++\EasyTshark\packets.pcap)";
	std::string options = " -T fields  -e frame.number -e frame.time -e frame.cap_len -e ip.src  -e ipv6.src -e ip.dst -e	ipv6.dst \
							-e tcp.srcport -e udp.srcport -e tcp.dstport  -e udp.dstport -e _ws.col.Protocol -e _ws.col.info";
	std::string cmd = exe_path + " -r " + packet_file + options;

	FILE* pipe = _popen(cmd.c_str(), "r");
	if (!pipe) {
		std::cout << "Failed to run tshark command";
		return 1;
	}

	std::vector<Packet> packets;
	char buffer[4096]{};

	IP2RegionUtil ip2region_util;
	ip2region_util.init(R"(D:\code\C++\EasyTshark\third_library\ip2region\ip2region.xdb)");

	// ��ȡpcapȫ���ļ�ͷ��ƫ����
	uint32_t file_offset = sizeof(PcapHeader);
	while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
		Packet packet;
		
		if (parse_line(buffer, packet)) {
			// ����ǰ����������pcap�ļ��е�ƫ����: ƫ���α� + ��ǰ���ݰ�ͷ ,����¼��packet������
			packet.file_offset = file_offset + sizeof(PacketHeader);

			// ����ƫ���α�, ָ����һ�����ݰ�
			file_offset = file_offset + sizeof(PacketHeader) + packet.cap_len;

			// ����Դ/Ŀ��ip������
			packet.src_location = ip2region_util.get_ip_location(packet.src_ip);
			packet.dst_location = ip2region_util.get_ip_location(packet.dst_ip);

			packets.push_back(packet);
		}
		else {
			// ����ʧ�ܣ�����ͻ����,����ʧ���Ų�����
			assert(false);
		}

	}

	for (auto& p : packets) {
		PrintPacket(p);

		// ��ȡ���ĵ�ԭʼʮ����������
		std::vector<unsigned char> data;
		read_packet_hex(packet_file, p.file_offset, p.cap_len, data);

		// ��ӡ��ȡ��������
		printf("Packet Hex: ");
		for (auto byte : data) {
			printf("%02X ", byte);
		}
		printf("\n\n");

	}
	_pclose(pipe);

	return 0;
}

