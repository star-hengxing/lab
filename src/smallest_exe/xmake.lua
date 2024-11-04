target("smallest")
    set_kind("binary")
    add_files("*.cpp")

    add_ldflags(
        "/entry:main",
        "/subsystem:windows",
        "/align:16",

        "/EMITPOGOPHASEINFO", -- remove debug dir
    {force = true, tools = "link"})

    add_syslinks("user32")

    after_build(function (target)
        local file = io.open(target:targetfile(), "r")
        local size, error = file:size()
        file:close()

        print("size:", size, "bytes")
    end)
