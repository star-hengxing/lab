includes("test")

add_rules("mode.release", "mode.debug")

set_languages("c++20")

add_requires("fast_io")

local configs = {configs = {
    shared = false,
    runtimes = "MT",
    cxflags = {
        "/EHsc-",
        "/GS-",
        "/sdl-",
        "/Zc:inline",
        "/kernel",
    }
}}

add_requires("fast-lzma2", configs)
add_requireconfs("fast-lzma2.**", configs)

target("pe-in-memory")
    set_kind("binary")
    set_runtimes("MD")
    add_files("pe-in-memory.cpp")
    add_packages("fast_io")

target("pe-packer")
    set_kind("binary")
    add_files("pe-packer.cpp")
    add_deps("pe-loader", {inherit = false})
    add_packages("fast_io", "fast-lzma2")

    on_config(function (target)
        local shellcode = target:dep("pe-loader"):targetfile()
        -- TODO: set nozeroend false
        target:add("files", shellcode, {rules ="utils.bin2c", always_added = true})
        -- target:add("defines", "SHELLCODE_HEADER" .. shellcode:filename() .. ".h")
    end)

    -- after_build(function (target)
    --     os.vexecv(target:targetfile(), {}, {curdir = target:targetdir()})
    -- end)

target("pe-loader")
    add_rules("shellcode", {pe = true})
    add_files("pe-loader.cpp")

    add_shflags("/subsystem:native", "-entry:loader", {tools = "link", force = true})
    -- set_runtimes("MD")
    add_links("ucrt", "vcruntime", "kernel32")

    add_packages("fast-lzma2")
    set_policy("build.fence", true)

target("shellcode")
    set_kind("object")
    add_rules("shellcode")
    add_files("shellcode/*.cpp", "shellcode/*.asm")

    add_includedirs("shellcode", {interface = true})

rule("shellcode")
    on_config(function (target)
        target:set("encodings", "source:utf-8")
        target:set("exceptions", "no-cxx")
        target:add("cxflags", "/permissive-", "/GS-", "/sdl-", "/fp:except-", "/Zc:inline", "/Gy", {tools = "cl"})
        target:add("cxflags", "/kernel", {tools = "cl", force = true})

        if not target:extraconf("rules", "shellcode", "pe") then
            return
        end

        target:set("kind", "shared")
        target:add("deps", "shellcode")

        local link_flags = {
            -- "/map",

            "/kernel",

            "/merge:.data=.text",
            "/merge:.rdata=.text",
            "/section:.text,RWE",

            "/DYNAMICBASE:NO",
            "/FIXED",
            "/EMITPOGOPHASEINFO",
        }
        target:add("ldflags", link_flags, {tools = "link", force = true})
        target:add("shflags", link_flags, {tools = "link", force = true})
    end)
