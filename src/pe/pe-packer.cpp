#include <string_view>
#include <vector>

#include <fast_io.h>
#include <fast-lzma2.h>

#include "base.hpp"

extern const std::string_view loader_code;

fixed_buffer compress(std::byte* data, size_t size)
{
    auto max_size = FL2_compressBound(size);
    auto buffer = std::unique_ptr<std::byte>(new std::byte[max_size]);
    auto compressed_size = FL2_compress(buffer.get(), max_size, data, size, 0);
    return {std::move(buffer), compressed_size};
}

std::vector<std::byte> shellcode_after_load_layout(){
    std::vector<std::byte> code;
    auto shell_nt = (PIMAGE_NT_HEADERS)(loader_code.data() + ((PIMAGE_DOS_HEADER)loader_code.data())->e_lfanew);
    code.resize(shell_nt->OptionalHeader.SizeOfImage);
    
    std::memcpy(code.data(), loader_code.data(), shell_nt->OptionalHeader.SizeOfHeaders);

    auto section = IMAGE_FIRST_SECTION(shell_nt);
    for (int i = 0; i < shell_nt->FileHeader.NumberOfSections; i += 1)
    {
        std::memcpy(
            code.data() + section[i].VirtualAddress,
            loader_code.data() + section[i].PointerToRawData,
            section[i].SizeOfRawData);
    }
    return code;
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        fast_io::io::println("Usage: <input pe>");
        fast_io::io::println("       <input pe> <output pe>");
        return -1;
    }
    auto const output_pe = std::string_view{argv[argc - 1]};

    PE src_pe;
    auto input = fast_io::native_file_loader{fast_io::manipulators::basic_os_c_str(argv[1])};
    src_pe.init((std::byte*)input.data());

    if (!(src_pe.is_dos() && src_pe.is_pe()))
    {
        return -1;
    }

    auto compressed = compress((std::byte*)input.data(), input.size());
    fast_io::io::println("Original size: ", input.size());
    fast_io::io::println("Compressed size: ", compressed.size);

    IMAGE_NT_HEADERS nt = *src_pe.nt;
    nt.FileHeader.NumberOfSections = 3;
    std::memset(&nt.OptionalHeader.DataDirectory, 0, sizeof(nt.OptionalHeader.DataDirectory));

    std::vector<std::byte> sections_data[3];
    IMAGE_SECTION_HEADER sections_header[3]{};

    sections_header[0].Misc.VirtualSize = src_pe.nt->OptionalHeader.SizeOfImage;
    sections_header[0].VirtualAddress = 0x1000;
    sections_header[0].PointerToRawData = 0x400;
    sections_header[0].Name[0] = 'h';
    sections_header[0].Name[1] = 'e';
    sections_header[0].Name[2] = 'l';
    sections_header[0].Name[3] = 'l';
    sections_header[0].Name[4] = 'o';
    sections_header[0].Name[5] = '\0';
    sections_header[0].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_UNINITIALIZED_DATA;
    nt.OptionalHeader.SizeOfUninitializedData = sections_header[0].Misc.VirtualSize;
    nt.OptionalHeader.SizeOfInitializedData = 0;

    sections_header[1].Name[0] = 's';
    sections_header[1].Name[1] = 'r';
    sections_header[1].Name[2] = 'c';
    sections_header[1].Name[3] = '\0';
    sections_header[1].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_INITIALIZED_DATA;

    compress_code_packet packet{};
    packet.compress_size = compressed.size;
    packet.uncompressed_size = input.size();
    sections_data[1].resize(compressed.size + sizeof(size_t) * 2);
    std::memcpy(sections_data[1].data(), &packet, sizeof(size_t) * 2);
    std::memcpy(sections_data[1].data() + sizeof(size_t) * 2, compressed.data.get(), compressed.size);

    sections_header[2].Name[0] = 'h';
    sections_header[2].Name[1] = 'i';
    sections_header[2].Name[2] = '\0';
    sections_header[2].Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_INITIALIZED_DATA;
    sections_data[2] = shellcode_after_load_layout();

    nt.OptionalHeader.SizeOfCode = 0;
    for (size_t i = 1; i < 3; i += 1)
    {
        auto& current = sections_header[i];
        auto& last = sections_header[i - 1];
        auto& data = sections_data[i];

        current.Misc.VirtualSize = ::align(data.size(), nt.OptionalHeader.SectionAlignment);
        current.VirtualAddress = last.VirtualAddress + last.Misc.VirtualSize;
        current.SizeOfRawData = ::align(data.size(), nt.OptionalHeader.FileAlignment);
        current.PointerToRawData = last.PointerToRawData + last.SizeOfRawData;

        data.resize(current.SizeOfRawData);
        nt.OptionalHeader.SizeOfInitializedData += current.SizeOfRawData;
        nt.OptionalHeader.SizeOfCode += current.Misc.VirtualSize;
    }
    nt.OptionalHeader.SizeOfImage = sections_header[2].VirtualAddress + sections_header[2].Misc.VirtualSize;

    auto shell_start = loader_code.data();
    auto shell_image_base = sections_header[2].VirtualAddress;
    auto shell_nt = (PIMAGE_NT_HEADERS)(shell_start + ((PIMAGE_DOS_HEADER)shell_start)->e_lfanew);
    nt.OptionalHeader.AddressOfEntryPoint = shell_image_base + shell_nt->OptionalHeader.AddressOfEntryPoint;

    size_t write_size{};
    auto output = fast_io::native_file{output_pe, fast_io::open_mode::out};
    write_size += src_pe.dos->e_lfanew;
    fast_io::io::print(output, std::string_view{input.data(), (size_t)src_pe.dos->e_lfanew});
    write_size += sizeof(IMAGE_NT_HEADERS);
    fast_io::io::print(output, std::string_view{(char*)&nt, sizeof(IMAGE_NT_HEADERS)});
    write_size += sizeof(sections_header);
    fast_io::io::print(output, std::string_view{(char*)&sections_header, sizeof(sections_header)});
    auto need_align = ::align(write_size, nt.OptionalHeader.FileAlignment) - write_size;
    if (need_align != 0)
    {
        std::vector<std::byte> align_data(need_align);
        fast_io::io::print(output, std::string_view{(char*)align_data.data(), align_data.size()});
    }

    for (size_t i = 1; i < 3; i += 1)
    {
        auto data = std::string_view{(char*)sections_data[i].data(), sections_data[i].size()};
        fast_io::io::print(output, data);
    }
}

// zero-terminated
unsigned char loader_code_data[] = {
#include "pe-loader.dll.h"
};

const std::string_view loader_code = {(char*)loader_code_data, sizeof(loader_code_data) - 1};
