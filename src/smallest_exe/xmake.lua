target("test")
    set_kind("binary")
    set_arch("x86")
    add_files("*.cpp")
    set_targetdir(path.join(os.projectdir(), "build", "smallest_exe"))

    add_ldflags(
        "/entry:main",
        "/subsystem:windows",
        "/align:16", {force = true})

    add_syslinks("user32")

    after_build(function (target)
        local file = io.open(target:targetfile(), "r")
        local size, error = file:size()
        file:close()

        print("size:", size, "bytes")
    end)
