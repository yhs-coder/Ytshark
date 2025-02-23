#ifndef __EXCEPTION_H__
#define __EXCEPTION_H__
/*
异常处理
*/

#include <string.h>

#include <stdexcept>
#include <string>

class IOException : public std::exception
{
public:
    IOException(const std::string &msg) : _code(errno), _msg(msg)
    {
        _msg.append(": ");
        _msg.append(strerror(_code));
    }
    // 委托构造函数
    IOException(const std::string &msg, const std::string &arg) : IOException(msg + ": " + arg)
    {
    }

    int code() const noexcept
    {
        return _code;
    }

    const char *what() const noexcept
    {
        return _msg.c_str();
    }

private:
    int _code;        // 错误码
    std::string _msg; // 错误信息
};

#endif //__EXCEPTION_H__