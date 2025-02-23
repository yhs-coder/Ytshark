#include <fstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdexcept>
#include <string>
#include <string.h>
#include <stdlib.h>

// IO异常处理
class IOException : public std::exception
{
    int code_;        // 错误码
    std::string msg_; // 错误信息

public:
    IOException(const std::string &msg) : code_(errno), msg_(msg)
    {
        // 拼接错误信息
        msg_.append(": ");
        msg_.append(strerror(code_));
    }

    // 错误信息 + 其它参数信息
    IOException(const std::string &msg, const std::string &arg)
        : IOException(msg + ": " + arg) {}

    // 返回错误码
    int code() const noexcept
    {
        return code_;
    }

    // 返回错误信息
    const char *what() const noexcept
    {
        return msg_.c_str();
    }
};

// 内存映射区域
class MappedBuffer
{
    char *map_addr_; // 内存映射区域的起始地址
    size_t map_len_; // 内存映射区域的长度

    MappedBuffer(char *map_addr, size_t map_len, char *data, size_t len)
        : map_addr_(map_addr), map_len_(map_len), data_(data), len_(len)
    {
    }
    // MappedBuffer(const MappedBuffer&) = delete;
    MappedBuffer &operator=(const MappedBuffer &) = delete;

public:
    char *data_; // (文件)数据在内存映射区的开始地址
    size_t len_; // (文件)映射的长度
    ~MappedBuffer()
    {
        ::munmap(map_addr_, map_len_);
    }
    friend class File;
};

// 文件操作
class File
{
    int fd_{-1};     // 文件描述符
    struct stat st_; //

public:
    // 打开文件，获取fd，并且获取到文件的属性
    File(const char *fname, int flags)
    {
        if ((fd_ = open(fname, flags)) == -1)
            throw IOException("connot open file", fname);
        if (fstat(fd_, &st_) != 0)
            throw IOException("fstat");
    }

    void close() noexcept
    {
        if (fd_ != -1)
        {
            ::close(fd_);
            fd_ = -1;
        }
    }

    int fd() const noexcept
    {
        return fd_;
    }

    // 得到文件的属性
    struct stat &stat()
    {
        return st_;
    }

    // 返回文件大小
    size_t size() const noexcept
    {
        return st_.st_size;
    }

    // 使用封装好的内存映射处理函数
    MappedBuffer map_readonly()
    {
        // 将文件的全部内容映射到内存中
        return map_readonly(0, size());
    }

    /*
        map_readonly: 允许指定要映射的文件偏移量和长度，将文件的一部分映射到内存中，以便于以只读的方式访问文件内容
        参数：     文件示意图
                    -----------------------------
                    | offset  |映射内容  |
                    -----------------------------
            offset：文件偏移量，就是要映射内容距离文件起始的偏移量，指定了文件映射内容的起点。
            length：要映射的文件长度
    */
    MappedBuffer map_readonly(off_t offset, size_t length)
    {
        // 检查传入的偏移量是否超出了文件的范围
        if (offset >= size())
            throw std::invalid_argument("offset is past end of file");

        // 计算出映射区域的实际长度，以确保不会超出文件的范围。
        if (offset + length > size())
            // 改变文件映射的长度
            length = size() - offset;

        // 根据传入的文件偏移量计算出页对齐的起始地址
        // sysconf(_SC_PAGE_SIZE) 获取系统页大小。
        // ~(sysconf(_SC_PAGE_SIZE) - 1) 生成一个掩码，用于将 offset 的低-order 位设置为 0，使其对齐到页边界。
        // offset & ~(sysconf(_SC_PAGE_SIZE) - 1) 通过位与运算将 offset 对齐到页边界。

        off_t page_offset = offset & ~(sysconf(_SC_PAGE_SIZE) - 1);
        // 调用 mmap 系统调用将文件映射到内存中。
        char *map_addr = (char *)::mmap(0, length + offset - page_offset, PROT_READ, MAP_PRIVATE, fd_, page_offset);
        if (map_addr == MAP_FAILED)
            throw IOException("mmap");
        char *data = map_addr + offset - page_offset;
        size_t map_len = length + offset - page_offset;
        return MappedBuffer{map_addr, map_len, data, length};
    }
    ~File() noexcept
    {
        close();
    }

    File(const File &) = delete;
    File &operator=(const File &) = delete;
};

void print_hex(char *d, size_t sz)
{
    for (size_t i = 0; i < sz; i++)
    {
        printf("%02X ", uint8_t(d[i]));
        if ((i + 1) % 8 == 0)
            printf("\n");
    }
    printf("\n");
}

int main(int argc, char const *argv[])
{
    try
    {
        File f("1.jpg", O_RDONLY);
        auto buffer = f.map_readonly();
        print_hex(buffer.data_, 64);
        print_hex(buffer.data_ + buffer.len_ - 64, 64);
    }
    catch (const std::exception &e)
    {
        fprintf(stderr, "exception:%s\n", e.what());
    }

    return 0;
}
