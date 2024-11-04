#include <Windows.h>

#include <fast-lzma2.h>

#include "base.hpp"
#include "GetProcAddress.h"

extern "C" {

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

    auto p_kernel32 = (HMODULE)::GetKernel32ModuleHandle();
    auto p_GetProcAddress = (fn_GetProcAddress)::GetAddressOf_GetProcAddress(p_kernel32);
    auto p_LoadLibraryA = (fn_LoadLibraryA)p_GetProcAddress(p_kernel32, "LoadLibraryA");

    for (; dll_desc->Characteristics; dll_desc += 1)
    {
        auto name = (char*)(image_base + dll_desc->Name);
        HMODULE hm = p_LoadLibraryA(name);
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
                auto address = (ULONG_PTR)p_GetProcAddress(hm, search_value);
                if (address)
                {
                    iat[i].u1.Function = address;
                }
            }
        }
    }
}

[[noreturn]] void loader()
{
    auto image_base = (std::byte*)::GetImageBase();

    PE shell_pe;
    shell_pe.init(image_base);

    auto section = IMAGE_FIRST_SECTION(shell_pe.nt);

    {
        auto shellcode_image_base = image_base + section[2].VirtualAddress;
        auto shell_nt = (PIMAGE_NT_HEADERS)(shellcode_image_base + ((PIMAGE_DOS_HEADER)shellcode_image_base)->e_lfanew);
        ::image_import((size_t)shellcode_image_base, shell_nt);
    }

    auto compress_code = (compress_code_packet*)(image_base + section[1].VirtualAddress);
    std::byte* target_pe_file = (std::byte*)std::malloc(compress_code->uncompressed_size);

    [[maybe_unused]] auto decompressed_size = ::FL2_decompress(
        target_pe_file,
        compress_code->uncompressed_size,
        &compress_code->data,
        compress_code->compress_size
    );

    PE target_pe;
    target_pe.init(target_pe_file);

    auto target_image_base = image_base + section[0].VirtualAddress;
    ::image_copy(target_pe_file, target_image_base, target_pe.nt);
    ::image_relocate((size_t)target_image_base, target_pe.nt);
    ::image_import((size_t)target_image_base, target_pe.nt);

    auto entry_point = target_image_base + target_pe.nt->OptionalHeader.AddressOfEntryPoint;
    std::free(target_pe_file);

    jump_to_entry_point(entry_point);
}

}
