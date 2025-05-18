#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        MessageBoxA(nullptr, "dll hijacking", nullptr, MB_OK | MB_ICONINFORMATION);
    }
    else if (fdwReason == DLL_PROCESS_DETACH)
    {
    }
    return TRUE;
}
