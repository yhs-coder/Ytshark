#pragma once
#include "ip2region/xdb_search.h"

#include <string>
#include <memory>

class IP2RegionUtil {
public:
    // ָ��xdb�ļ������г�ʼ��
    static bool init(const std::string& xdb_file_path);
    // ��ȡIP��ַ������
    static std::string get_ip_location(const std::string& ip);

private:
    // // ����IP��ַ����ʽ������λ��
    static std::string parse_location(const std::string& input);
    static std::shared_ptr<xdb_search_t> _xdb_ptr;
};


