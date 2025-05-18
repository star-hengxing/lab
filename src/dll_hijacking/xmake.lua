add_moduledirs("modules")

target("dll_hijacking_test")
    set_kind("binary")
    add_files("main.c")
    add_syslinks("version")

target("mydll")
    set_kind("shared")
    add_files("main.cpp")
    add_syslinks("user32")

target("version")
    add_rules("c")
    add_rules("dll_hijacking", {import = "mydll.dll"})
    add_files("C:/windows/system32/version.dll")

rule("dll_hijacking")
    set_extensions(".dll")

    on_config("windows", function (target)
        target:set("kind", "shared")
        target:add("shflags", "-entry:init", {force = true})
        target:add("syslinks", "kernel32", "shlwapi")
    end)

    on_prepare_files(function (target, jobgraph, sourcebatch, opt)
        import("core.project.depend")
        import("utils.progress")
        import("pe", {always_build = true})

        local autogendir = path.join(target:autogendir(), "rules/dll_hijacking")
        for _, sourcefile in ipairs(sourcebatch.sourcefiles) do
            local job_name = path.join(target:fullname(), "generate/dll", sourcefile)
            jobgraph:add(job_name, function (index, total, job_opt)
                depend.on_changed(function()
                    progress.show(job_opt.progress or 0, "${color.build.object}reading.dll %s", sourcefile)
                    local symbols = pe.get_exports(sourcefile)
                    local dll_c_file = path.join(autogendir, path.basename(sourcefile) .. ".c")

                    local dll_file = io.open(dll_c_file, "w")
                    dll_file:print([[
                        #include <windows.h>
                        #include <shlwapi.h>
                        typedef struct {
                            FARPROC fn;
                            LPCSTR name;
                        }fn_payload;
                        static HMODULE ori_dll_module;
                        static fn_payload exports[] = {
                    ]])
                    for _, symbol in ipairs(symbols) do
                        dll_file:print([[{.name = "%s"},]], symbol)
                    end
                    dll_file:print("};")
                    for i, symbol in ipairs(symbols) do
                        local name = symbol
                        dll_file:print("void WINAPI stub_%s() {", name)
                        dll_file:print([[#pragma comment(linker, "/EXPORT:%s=stub_%s")]], name, name)
                        dll_file:print("exports[%d].fn();", i - 1)
                        dll_file:print("}")
                    end
                    dll_file:print([[
                        BOOL WINAPI init(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
                            char dll_path[MAX_PATH];
                            GetSystemDirectoryA(dll_path, MAX_PATH);
                            PathAppendA(dll_path, "\\%s.dll");
                            ori_dll_module = LoadLibraryA(dll_path);
                            for (int i = 0; i < %d; i++) {
                                exports[i].fn = GetProcAddress(ori_dll_module, exports[i].name);
                            }
                    ]], target:name(), #symbols)
                    local import_dll = target:extraconf("rules", "dll_hijacking", "import")
                    if import_dll then
                        dll_file:print('LoadLibraryA("%s");', import_dll)
                    end
                    dll_file:print("return TRUE;}")
                    dll_file:close()
                end, {
                    files = sourcefile,
                    dependfile = target:dependfile(sourcefile),
                    changed = target:is_rebuilt()
                })
            end)
        end
    end, {jobgraph = true})

    on_build_files(function (target, jobgraph, sourcebatch, opt)
        local batchcxx = {
            rulename = "c.build",
            sourcekind = "cc",
            sourcefiles = {},
            objectfiles = {},
            dependfiles = {}
        }
        local autogendir = path.join(target:autogendir(), "rules/dll_hijacking")
        for _, sourcefile in ipairs(sourcebatch.sourcefiles) do
            local dll_c_file = path.join(autogendir, path.basename(sourcefile) .. ".c")
            local objectfile = target:objectfile(dll_c_file)
            local dependfile = target:dependfile(objectfile)
            table.insert(target:objectfiles(), objectfile)
            table.insert(batchcxx.sourcefiles, dll_c_file)
            table.insert(batchcxx.objectfiles, objectfile)
            table.insert(batchcxx.dependfiles, dependfile)
            import("private.action.build.object")(target, jobgraph, batchcxx, opt)
        end
    end, {jobgraph = true, distcc = true})
