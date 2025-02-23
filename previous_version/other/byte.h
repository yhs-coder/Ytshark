#ifndef __BYTE_H__
#define __BYTE_H__

/*
该模块的作用是处理字节序。
将网络字节序转换为主机字节序
*/
#include <cstdint> // 定义了固定宽度的整数类型，如 int32_t、uint64_t 等。
#include <sys/types.h>

// 将uint8_t定义别名为byte
using byte = uint8_t;

/*
@return 字节序
*/
struct Endian
{
    int static get_endian()
    {
        uint32_t value = 0x1A2B3C4D;
        // 判断大小端
        return *(reinterpret_cast<u_char *>(&value)) == 0x1A ? BIG_ENDIAN : LITTLE_ENDIAN;
    }

    /*
    @return bool - true表示是主机字节序
    */
    bool static is_little_endian()
    {
        return get_endian() == LITTLE_ENDIAN;
    }
};

/*
    byte_swap: 字节序转换函数：
    分别对1、2、4字节的数据进行字节序转换

*/

// 一字节的数据不需要进行字节序转换
inline constexpr uint8_t byte_swap(uint8_t x)
{
    return x;
}

// 2字节
inline constexpr uint16_t byte_swap(uint16_t x)
{
    return ((x & 0xff) << 8) | ((x & 0xff00) >> 8);
}

inline constexpr uint32_t byte_swap(uint32_t x)
{
    return ((x << 24) & 0xff000000) | ((x << 8) & 0xff0000) |
           ((x >> 8) & 0xff00) | ((x >> 24) & 0xff);

    // 更加清晰易懂的写法
    // return ((((x) & 0x000000ff) << 24) | (((x) & 0x0000ff00) << 8) |
    //       (((x) & 0x00ff0000) >> 8) | (((x) & 0xff000000) >> 24));
}

// C++14：返回类型推导 auto 和尾置返回类型 -> T
// 根据系统的字节序返回原始值或转换后的值
template <typename T>
inline auto to_host(T x) -> T
{
    // 如果本机系统是网络字节序，则直接返回，无需转换
    if (!Endian::is_little_endian())
        return x;
    return byte_swap(x);
}

// 将指针转换为指定类型，并获得该值
template <typename T>
inline auto as(const void *d) -> T
{
    return *reinterpret_cast<const T *>(d);
}

// 先转换指针为指定类型，再用 to_host 函数进行字节序转换
template <typename T>
inline auto as_host(const void *d) -> T
{
    return to_host(*reinterpret_cast<const T *>(d));
}

#endif // __BYTE_H__