#include <Windows.h>

int main()
{
    while (true)
    {
        ::MessageBoxW(nullptr, L"Hello world!", L"Title", MB_OK | MB_ICONINFORMATION);
    }
}
