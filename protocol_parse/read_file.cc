#include <fstream>
#include <assert.h>

void print_data(auto &f, size_t size)
{
    for (size_t i = 0; i < size && !f.eof(); i++)
    {
        printf("%02X ", f.get());
        if ((i + 1) % 8 == 0)
            printf("\n");
    }
    printf("\n");
}

int main(int argc, char const *argv[])
{
    std::ifstream f("1.jpg", std::ios::binary);
    assert(f.good());

    print_data(f, 64);
    f.seekg(-64, std::ios::end);
    print_data(f, 64);
    return 0;
}
