set_project("lab")

set_xmakever("3.0.0")

add_rules("plugin.compile_commands.autoupdate", {outputdir = "build", lsp = "clangd"})

includes("src")
includes("xmake/option.lua")
