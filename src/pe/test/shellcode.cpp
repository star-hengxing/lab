#include <cstring>

#include <Windows.h>

#include <fast_io.h>
#include <GetProcAddress.h>

void image_copy(char* src, char* dst, PIMAGE_NT_HEADERS nt)
{
    std::memcpy(dst, src, nt->OptionalHeader.SizeOfHeaders);

    auto section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i += 1)
    {
        std::memcpy(
            dst + section[i].VirtualAddress,
            src + section[i].PointerToRawData,
            section[i].SizeOfRawData);
    }
}

void image_relocate(size_t image_base, PIMAGE_NT_HEADERS nt)
{
    auto data_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    auto current_page_ptr = (char*)image_base + data_dir->VirtualAddress;
    auto const end = current_page_ptr + data_dir->Size;

    auto const delta = image_base - nt->OptionalHeader.ImageBase;

    while (current_page_ptr < end)
    {
        auto const current_reloc_table = (PIMAGE_BASE_RELOCATION)current_page_ptr;
        auto const current_entry_end = (uint16_t*)(current_page_ptr + current_reloc_table->SizeOfBlock);
        auto current_entry = (uint16_t*)(current_reloc_table + 1);

        for (; current_entry < current_entry_end; current_entry += 1)
        {
            auto need_reloc_address = (char*)image_base + current_reloc_table->VirtualAddress + ((*current_entry) & 0x0fff);
            // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#base-relocation-types
            switch ((*current_entry) >> 12)
            {
            case IMAGE_REL_BASED_LOW:
                *((uint16_t*)need_reloc_address) += LOWORD(delta);
                break;
            case IMAGE_REL_BASED_HIGH:
                *((uint16_t*)need_reloc_address) += HIWORD(delta);
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                *((uint32_t*)need_reloc_address) += (int32_t)delta;
                break;
            case IMAGE_REL_BASED_DIR64:
                *((uint64_t*)need_reloc_address) += delta;
            case IMAGE_REL_BASED_ABSOLUTE:
                break; // skip
            default:
                // unimplemented
                break;
            }
        }
        current_page_ptr += current_reloc_table->SizeOfBlock;
    }
}

void image_import(size_t image_base, PIMAGE_NT_HEADERS nt)
{
    auto data_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto dll_desc = (PIMAGE_IMPORT_DESCRIPTOR)(image_base + data_dir->VirtualAddress);

    for (; dll_desc->Characteristics; dll_desc += 1)
    {
        auto name = (char*)(image_base + dll_desc->Name);
        HMODULE hm = ::LoadLibraryA(name);
        if (hm)
        {
            const char* search_value;
            auto orig_first_thunk = (PIMAGE_THUNK_DATA)(image_base + dll_desc->OriginalFirstThunk);
            auto iat = (PIMAGE_THUNK_DATA)(image_base + dll_desc->FirstThunk);

            for (int i = 0; orig_first_thunk[i].u1.AddressOfData; i += 1)
            {
                auto ordinal = orig_first_thunk[i].u1.Ordinal;
                if (ordinal & IMAGE_ORDINAL_FLAG)
                {
                    search_value = (const char*)IMAGE_ORDINAL(ordinal);
                }
                else
                {
                    auto by_name = (PIMAGE_IMPORT_BY_NAME)(image_base + iat[i].u1.AddressOfData);
                    search_value = (const char*)by_name->Name;
                }
                auto address = (ULONG_PTR)::GetProcAddress(hm, search_value);
                if (address)
                {
                    iat[i].u1.Function = address;
                }
            }
        }
    }
}

void test_shellcode_run()
{
    auto pe = fast_io::native_file_loader{"packer-loader.dll"};

    auto nt = (PIMAGE_NT_HEADERS)(pe.data() + ((PIMAGE_DOS_HEADER)pe.data())->e_lfanew);

    auto image_base = ::VirtualAlloc(nullptr, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    image_copy(pe.data(), (char*)image_base, nt);
    image_import((size_t)image_base, nt);
    union
    {
        void* p;
        BOOL(WINAPI* dll_entry)(HINSTANCE, DWORD, LPVOID);
        void(WINAPI* exe_entry)(void);
    } u;

    u.p = (std::byte*)image_base + nt->OptionalHeader.AddressOfEntryPoint;

    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL)
    {
        if (!u.dll_entry((HINSTANCE)image_base, DLL_PROCESS_ATTACH, NULL))
            return;
        if (!u.dll_entry((HINSTANCE)image_base, DLL_THREAD_ATTACH, NULL))
            return;
    }
    else
    {
        u.exe_entry();
    }

    ::VirtualFree(image_base, 0, MEM_RELEASE);
    
}

int main()
{
    auto except = ::GetProcAddress;
    auto test = GetAddressOf_GetProcAddress(GetKernel32ModuleHandle());

    bool result = true;
    result &= (test == except);
    result &= (reinterpret_cast<uintptr_t>(GetImageBase()) == 0x140000000);
    if (!result)
    {
        return 1;
    }
    
    test_shellcode_run();
}
