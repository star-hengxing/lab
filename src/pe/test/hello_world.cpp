#include <cstdio>

extern "C"
{
    int a = 0x12345678;
}

int main(int argc, char* argv[])
{
    std::printf("value: 0x%x address: 0x%p\n", a, &a);
}
