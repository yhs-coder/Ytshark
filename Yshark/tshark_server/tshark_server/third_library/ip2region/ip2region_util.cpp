//
// Created by xuanyuan on 2024/10/17.
//

#include "ip2region_util.h"
#include "misc_util.hpp"
#include "ip2region_xdb_data.h"
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

std::shared_ptr<xdb_search_t> IP2RegionUtil::xdbPtr;

bool IP2RegionUtil::init(const std::string& xdbFilePath) {

    // 如果xdb数据文件不在，则释放之
    if (!MiscUtil::fileExists(xdbFilePath)) {
        std::ofstream ofs(xdbFilePath, std::ios::binary);
        if (!ofs) return false;

        // 将数组数据写入磁盘
        ofs.write(reinterpret_cast<const char*>(ip2region_xdb), ip2region_xdb_len);
        ofs.close();
    }

    xdbPtr = std::make_shared<xdb_search_t>(xdbFilePath);
    xdbPtr->init_content();
    return true;
}

void IP2RegionUtil::uninit() {
    xdbPtr.reset();
}

std::string IP2RegionUtil::getIpLocation(const std::string& ip) {

    //if is IPv6, return empty string
    if (ip.size() > 15) {
        return "";
    }

    std::string location = xdbPtr->search(ip);
    if (!location.empty() && location.find("invalid") == std::string::npos) {
        return parseLocation(location);
    } else {
        return "";
    }
}

std::string IP2RegionUtil::parseLocation(const std::string& input) {
    std::vector<std::string> tokens;
    std::string token;
    std::stringstream ss(input);

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
