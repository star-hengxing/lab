set_project("lab")

set_xmakever("2.7.9")

set_warnings("all")
set_languages("c++20")

add_rules("mode.debug", "mode.release")

if is_mode("debug") then
    set_policy("build.warning", true)
    add_requireconfs("*", {configs = {shared = true}})
end
-- support utf-8 on msvc
if is_host("windows") then
    add_defines("UNICODE", "_UNICODE")
    add_cxflags("/source-charset:utf-8", {tools = "cl"})
end

if is_plat("windows") then
    set_runtimes(is_mode("debug") and "MDd" or "MD")
end

add_includedirs("src")

includes("src")
