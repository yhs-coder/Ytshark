#include "map_file.h"


MapFile::MapFile()
    : _fd(INVALID_FILE)
    , _file_size(0)
    , _offset(0)
    , _map_len(0)
    , _map_addr(nullptr)
{}

MapFile::~MapFile()
{
    close_file();
}


void MapFile::cancel_map()
{
    if (_map_addr != nullptr)    
    {
        munmap(_map_addr, _map_len);
        _map_addr = nullptr;
        _map_len = 0;
    }
}

void MapFile::close_file()
{
    // 取消映射
    cancel_map();
    if (_fd != INVALID_FILE)
    {
        ::close(_fd);
        _fd = INVALID_FILE;
    }
}


/*
 *  打开文件并初始化MapFile
 *  错误码errno
 * */
int MapFile::open_file(const char *fname, int flags)
{
    // 如果此时PcapFile对象还没有关闭文件，
    // 又用这个对象加载了新的文件
    if (_fd != INVALID_FILE)
    {
        printf("关闭PcapFile对象的_fd,重新加载新的文件\n");
        close_file();
    }

    if ((_fd = open(fname, flags)) == INVALID_FILE)
        return errno;

    struct stat st;
    if (fstat(_fd, &st) == -1)
        return errno; 
    _file_size = st.st_size;
    return 0;
}

/*
 *  映射文件内容到内存
 *  @param offset -- 映射文件的起始偏移量，默认为0，即全部映射到内存
 *  #param map_len -- 映射内存的大小，默认为0， 为0时映射大小设置为文件大小
 *  return int -- 错误码errno
 * */
int MapFile::mmap_file(int protect_mode, int flags, int offset, int map_len)
{
    // 检查映射的长度
    if (map_len <= 0)
        map_len = _file_size;
    
    // 如果文件偏移量offset加上map_len映射长度 大于文件大小
    // 调整map_len映射的长度
    if (offset + map_len > (int)_file_size)
        map_len = _file_size - offset;

    void *map_addr = nullptr;
    map_addr = mmap(0, map_len, protect_mode, flags, _fd, offset);
    
    if (map_addr == nullptr)
        return errno;
   
    // 设置MapFile对象中成员的值
    _map_len = map_len;
    _map_addr = map_addr;
    _offset = offset;
    //printf("_map_addr: %p, _map_len: %d _offset: %d\n",_map_addr, _map_len, _offset);
    return 0;
}

/*
 *  获取文件内容
 *  @offset 相对内存映射区起始地址的偏移量
 *  @size   文件要映射内容大小
 *  @return 对应数据区域指针，失败返回空
 * */
void* MapFile::get_buffer(uint32_t offset, uint32_t size)
{
    
   // printf("_map_addr: %p - _map_len: %d offset: %d size: %d\n",_map_addr, _map_len, offset, size);
    if (_map_addr != nullptr && _map_len >= offset + size)
        return ((u_char*)_map_addr) + offset;  // 移动到文件内容映射的位置
  
    return nullptr;
}
