#include <fast_io.h>

#include "base.hpp"

void image_copy(std::byte* src, std::byte* dst, PIMAGE_NT_HEADERS nt)
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
    if (!data_dir->VirtualAddress || !data_dir->Size)
    {
        return;
    }

    auto current_page_ptr = (std::byte*)image_base + data_dir->VirtualAddress;
    auto const end = current_page_ptr + data_dir->Size;
    auto const delta = image_base - nt->OptionalHeader.ImageBase;

    while (current_page_ptr < end)
    {
        auto const current_reloc_table = (PIMAGE_BASE_RELOCATION)current_page_ptr;
        auto const current_entry_end = (uint16_t*)(current_page_ptr + current_reloc_table->SizeOfBlock);
        auto current_entry = (uint16_t*)(current_reloc_table + 1);

        for (; current_entry < current_entry_end; current_entry += 1)
        {
            // offset: 12 bit, type: 4 bit
            auto need_reloc_address = (std::byte*)image_base + current_reloc_table->VirtualAddress + ((*current_entry) & 0x0fff);
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
    if (!data_dir->VirtualAddress || !data_dir->Size)
    {
        return;
    }

    auto dll_desc = (PIMAGE_IMPORT_DESCRIPTOR)(image_base + data_dir->VirtualAddress);

    using fn_GetProcAddress = FARPROC(WINAPI*)(HMODULE, LPCSTR);
    using fn_LoadLibraryA = HMODULE(WINAPI*)(LPCSTR);

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

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        fast_io::io::perrln("Usage: <pe file>");
        return -1;
    }

    PE pe{};
    auto const file = fast_io::native_file_loader{fast_io::manipulators::os_c_str(argv[1])};

    pe.init((std::byte*)file.data());
    if (!pe.is_dos() || !pe.is_pe())
    {
        return -1;
    }

    auto const image_base = ::VirtualAlloc(nullptr, pe.nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!image_base)
    {
        return -1;
    }

    image_copy((std::byte*)file.data(), (std::byte*)image_base, pe.nt);
    image_relocate((size_t)image_base, pe.nt);
    image_import((size_t)image_base, pe.nt);

    union
    {
        std::byte* p;
        BOOL(WINAPI* dll_entry)
        (HINSTANCE, DWORD, LPVOID);
        void(WINAPI* exe_entry)();
    } tmp;

    tmp.p = (std::byte*)image_base + pe.nt->OptionalHeader.AddressOfEntryPoint;
    if (pe.nt->FileHeader.Characteristics & IMAGE_FILE_DLL)
    {
        if (!tmp.dll_entry((HINSTANCE)image_base, DLL_PROCESS_ATTACH, nullptr))
            return -1;
        if (!tmp.dll_entry((HINSTANCE)image_base, DLL_THREAD_ATTACH, nullptr))
            return -1;
    }
    else
    {
        tmp.exe_entry();
    }
}
