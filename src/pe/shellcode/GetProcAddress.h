// #include <winnt.h>
// #include <winternl.h>

extern "C"
{
    // void* GetImageBase(){
    //     return (void*)*((DWORD64*)((unsigned char*)reinterpret_cast<PPEB>(__readgsqword(0x60)) + 0x10));
    // }
    // void* GetKernel32ModuleHandle(){
    //     return (void*)*((DWORD64*)(0x20 + (unsigned char*)reinterpret_cast<PPEB>(__readgsqword(0x60))
    //         ->Ldr
    //         ->InMemoryOrderModuleList.Flink
    //         ->Flink
    //         ->Flink));
    // }

    void* GetImageBase();
    void* GetKernel32ModuleHandle();
    void* GetAddressOf_GetProcAddress(void* kernel32);
    [[noreturn]] void jump_to_entry_point(void* entry_point);
};
