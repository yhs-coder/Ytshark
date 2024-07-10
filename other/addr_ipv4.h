#ifndef __ADDR_IPV4_H__
#define __ADDR_IPV4_H__

#include <string>
#include <netinet/in.h>

struct AddrIPv4 : in_addr
{
    AddrIPv4() = default;
    AddrIPv4(uint32_t addr)
    {
        s_addr = addr;
    }
    std::string to_string() const
    {
        const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&s_addr);
        return std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) + "." +
               std::to_string(bytes[2]) + "." + std::to_string(bytes[3]);
    }

    bool operator<(const AddrIPv4 &r) const noexcept
    {
        return s_addr < r.s_addr;
    }
};
#endif // __ADDR_IPV4_H__