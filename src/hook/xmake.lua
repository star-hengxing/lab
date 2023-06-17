add_requires("microsoft-detours")

add_defines("WIN32_LEAN_AND_MEAN")

target("test")
    set_kind("binary")
    add_files("test.cpp")
    add_syslinks("user32")

target("hook64")
    set_kind("shared")
    add_files("hook.cpp")
    add_syslinks("user32")

    add_packages("microsoft-detours")

target("main")
    set_kind("binary")
    add_files("main.cpp")

    add_packages("microsoft-detours")
