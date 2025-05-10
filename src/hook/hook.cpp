#include <cstdlib>

#include <windows.h>
#include <detours.h>

// https://github.com/microsoft/Detours/wiki/DetourCreateProcessWithDll#remarks
#pragma comment(linker, "/export:DetourFinishHelperProcess,@1,NONAME")

namespace original
{

static auto MessageBoxW = ::MessageBoxW;

} // namespace original

namespace hook
{

int WINAPI MessageBoxW(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCWSTR lpText,
    _In_opt_ LPCWSTR lpCaption,
    _In_ UINT uType)
{
    original::MessageBoxW(hWnd, L"Hook!", lpCaption, uType);
    std::exit(0);
}

} // namespace hook

static void attach() noexcept
{
    auto src = std::addressof(reinterpret_cast<PVOID&>(original::MessageBoxW));
    auto dst = reinterpret_cast<PVOID>(hook::MessageBoxW);
    ::DetourAttach(src, dst);
}

static void detach() noexcept
{
    auto src = std::addressof(reinterpret_cast<PVOID&>(original::MessageBoxW));
    auto dst = reinterpret_cast<PVOID>(hook::MessageBoxW);
    ::DetourDetach(src, dst);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (DetourIsHelperProcess())
        return TRUE;

    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        ::DetourRestoreAfterWith();

        ::DetourTransactionBegin();
        ::DetourUpdateThread(GetCurrentThread());

        ::attach();

        ::DetourTransactionCommit();
    }
    else if (fdwReason == DLL_PROCESS_DETACH)
    {
        ::DetourTransactionBegin();
        ::DetourUpdateThread(GetCurrentThread());

        ::detach();

        ::DetourTransactionCommit();
    }
    return TRUE;
}
