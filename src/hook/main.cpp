#include <windows.h>
#include <detours.h>

static auto constexpr dll_path = "hook64.dll";

int main()
{
    PROCESS_INFORMATION process_info{};
    STARTUPINFOW startup_info
    {
        .cb = sizeof(startup_info),
    };

    BOOL result = ::DetourCreateProcessWithDllExW(
        L"test.exe", nullptr, nullptr,
        nullptr, FALSE, CREATE_DEFAULT_ERROR_MODE, nullptr, nullptr,
        &startup_info, &process_info, dll_path, nullptr);

    if (result == FALSE)
    {
        return -1;
    }
}
