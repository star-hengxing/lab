#pragma once

#include <memory>

#include <Windows.h>

struct fixed_buffer
{
    std::unique_ptr<std::byte> data;
    size_t size;
};

struct PE
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;

    void init(std::byte* data)
    {
        dos = (PIMAGE_DOS_HEADER)data;
        nt = (PIMAGE_NT_HEADERS)((std::byte*)dos + dos->e_lfanew);
    }

    bool is_dos() noexcept
    {
        return dos->e_magic == IMAGE_DOS_SIGNATURE;
    }

    bool is_pe() noexcept
    {
        return nt->Signature == IMAGE_NT_SIGNATURE;
    }

    bool is_64() noexcept
    {
        return nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 && nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    }

    bool is_dll() noexcept
    {
        return nt->FileHeader.Characteristics & IMAGE_FILE_DLL;
    }
};

struct compress_code_packet
{
    size_t compress_size;
    size_t uncompressed_size;
    std::byte* data;
};

inline constexpr size_t align(size_t input, size_t alignment)
{
    // auto const remainder = input % alignment;
    // return remainder ? input + alignment - remainder : input;
    return (input + alignment - 1) & ~(alignment - 1);
}
