#include <Windows.h>

bool string_cmp(const char* left, const char* right) noexcept
{
    while (*left && *right)
    {
        if (*left != *right)
        {
            return false;
        }
        left += 1;
        right += 1;
    }
    return *left == *right;
}

extern "C" void* GetAddressOf_GetProcAddress(void* p_kernel32)
{
    auto nt = (PIMAGE_NT_HEADERS)((unsigned char*)p_kernel32 + ((PIMAGE_DOS_HEADER)p_kernel32)->e_lfanew);
    auto data_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto export_dir = (PIMAGE_EXPORT_DIRECTORY)((unsigned char*)p_kernel32 + data_dir->VirtualAddress);
    auto address_of_functions = (DWORD*)((unsigned char*)p_kernel32 + export_dir->AddressOfFunctions);
    auto address_of_names = (DWORD*)((unsigned char*)p_kernel32 + export_dir->AddressOfNames);
    auto address_of_name_ordinals = (WORD*)((unsigned char*)p_kernel32 + export_dir->AddressOfNameOrdinals);
    for (DWORD i = 0; i < export_dir->NumberOfNames; i += 1)
    {
        auto name = (const char*)((unsigned char*)p_kernel32 + address_of_names[i]);
        if (string_cmp(name, "GetProcAddress"))
        {
            return (void*)((unsigned char*)p_kernel32 + address_of_functions[address_of_name_ordinals[i]]);
        }
    }
    return nullptr;
}
