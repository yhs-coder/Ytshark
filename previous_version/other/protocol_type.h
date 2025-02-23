#ifndef __PROTOCOL_TYPE_H__
#define __PROTOCOL_TYPE_H__

#include <stdint.h>

enum class ProtocolType : uint8_t
{
    Reserved = 0,    // 保留Reserved
    ICMP = 1,        // ICMP Internet Control Message [RFC792]
    IP = 4,          // IP in IP (encapsulation) [RFC2003]
    TCP = 6,         // TCP Transmission Control Protocol [RFC793]
    UDP = 17,        // UDP User Datagram Protocol [RFC768]      // NARP (NBMA Address Resolution Protocol) [RFC1735]
    IPv6_ICMP = 58,  // IPv6-ICMP (ICMP for IPv6) [RFC1883]
    IPv6_NoNxt = 59, // IPv6-NoNxt (No Next Header for IPv6) [RFC1883]
    IPv6_Opts = 60,  // IPv6-Opts (Destination Options for IPv6) [RFC1883]
};

inline const char *to_string(ProtocolType t)
{
    // using enum ProtocolType;
    switch (t)
    {
    case ProtocolType::Reserved:
        return "Reserved";
    case ProtocolType::ICMP:
        return "ICMP";
    case ProtocolType::IP:
        return "IP";
    case ProtocolType::TCP:
        return "TCP";
    case ProtocolType::UDP:
        return "UDP";
    case ProtocolType::IPv6_ICMP:
        return "IPv6_ICMP";
    case ProtocolType::IPv6_Opts:
        return "IPv6_Opts";
    default:
        return "";
    }
}

#endif //  __PROTOCOL_TYPE_H__