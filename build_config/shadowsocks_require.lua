option("ss2022")
    set_default(false)
    set_showmenu(true)
    set_description("Enable experimental Shadowsocks 2022 primitives")
option_end()
if is_plat("linux") and has_config("ss2022") then
    add_requires("nexus-blake3 1.8.4", {system = false})
end
