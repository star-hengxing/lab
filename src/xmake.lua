local labs = {
    "hook",
    "smallest_exe",
    "pe",
    "dll_hijacking",
}

for _, lab in ipairs(labs) do
    if has_config(lab) then
        includes(lab)
    end
end
