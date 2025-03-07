#include "ip2region_util.h"
#include "ip2region_util.h"
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include "utf8_to_ansi.h"

std::shared_ptr<xdb_search_t> IP2RegionUtil::_xdb_ptr;

bool IP2RegionUtil::init(const std::string& xdb_file_path) {

    _xdb_ptr = std::make_shared<xdb_search_t>(xdb_file_path);
    _xdb_ptr->init_content();
    return true;
}

std::string IP2RegionUtil::get_ip_location(const std::string& ip) {

    //if is IPv6, return empty string
    if (ip.size() > 15) {
        return "";
    }

    std::string location = _xdb_ptr->search(ip);
    if (!location.empty() && location.find("invalid") == std::string::npos) {
        return parse_location(location);
    }
    else {
        return "";
    }
}

std::string IP2RegionUtil::parse_location(const std::string& input) {
    // 编码转换，避免乱码
    //std::string content = UTF8TOANSIString(input);
    std::vector<std::string> tokens;
    std::string token;
    std::stringstream ss(input);

    // 默认的region信息格式： 国家 | 区域 | 省份 | 城市 | ISP

    if (input.find("内网") != std::string::npos) {
        return "内网";
    }

    while (std::getline(ss, token, '|')) {
        tokens.push_back(token);
    }

    if (tokens.size() >= 4) {
        std::string result;
        if (tokens[0].compare("0") != 0) {
            result.append(tokens[0]);
        }
        if (tokens[2].compare("0") != 0) {
            result.append("-" + tokens[2]);
        }
        if (tokens[3].compare("0") != 0) {
            result.append("-" + tokens[3]);
        }

        return result;
    }
    else {
        return input;
    }
}