#include <windows.h>

int main()
{
    GetFileVersionInfoA("C:\\Windows\\System32\\kernel32.dll", NULL, 0, NULL);
}
