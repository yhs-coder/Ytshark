#ifndef IP2REGION_UTIL_H
#define IP2REGION_UTIL_H
#include "ip2region/xdb_search.h"

#include <string>
#include <memory>

class IP2RegionUtil {
public:
    // 指定xdb文件，进行初始化
    static bool init(const std::string& xdb_file_path);
    // 获取IP地址归属地
    static std::string get_ip_location(const std::string& ip);

private:
    // // 解析IP地址，格式化地理位置
    static std::string parse_location(const std::string& input);
    static std::shared_ptr<xdb_search_t> _xdb_ptr;
};

#endif
