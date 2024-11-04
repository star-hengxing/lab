-- add_requires("vc-ltl5")
-- add_packages("vc-ltl5")

target("test-hello_world")
    set_kind("binary")
    add_files("hello_world.cpp")
    set_runtimes("MT")

target("test-shellcode")
    set_kind("binary")
    set_runtimes("MT")
    add_ldflags("/DYNAMICBASE:NO", "/EMITPOGOPHASEINFO")

    add_files("shellcode.cpp")
    
    add_deps("shellcode")
    add_deps("pe-loader", {inherit = false})
    add_packages("fast_io")

    add_tests("GetProcAddress")
