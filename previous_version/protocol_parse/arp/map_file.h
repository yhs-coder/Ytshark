#ifndef __MAP_FILE_H__
#define __MAP_FILE_H__
#include "base.h"

class MapFile
{
public:
    MapFile();
    ~MapFile();

    // 取消映射
    void cancel_map();
    // 关闭文件
    void close_file();
    // 打开文件
    int open_file(const char *fname, int flags);
    int mmap_file(int protect_mode, int flags, int offset = 0, int map_len = 0);
    void *get_buffer(uint32_t offset, uint32_t size);

    int _fd;                // 文件句柄
    uint32_t _file_size;    // 文件大小
    uint32_t _offset;       // 文件偏移量
    uint32_t _map_len;      // 映射区的长度
    void *_map_addr;        // 映射起始地址
};


#endif

