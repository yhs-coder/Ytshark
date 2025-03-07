//
// Created by xuanyuan on 2024/10/17.
//

#ifndef IP2REGION_UTIL_H
#define IP2REGION_UTIL_H

#include <string>
#include "xdb_search.h"
#include <memory>

class IP2RegionUtil {
public:
    static bool init(const std::string& xdbFilePath);
    static void uninit();
    static std::string getIpLocation(const std::string& ip);

private:
    static std::string parseLocation(const std::string& input);
    static std::shared_ptr<xdb_search_t> xdbPtr;
};

#endif //IP2REGION_UTIL_H
