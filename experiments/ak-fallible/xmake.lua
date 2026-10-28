set_project("nexus-ak-fallible-probe")
set_languages("c++26")
set_policy("build.c++.modules", true)
add_cxxflags("-fno-exceptions", {force = true})
local ak_source = os.getenv("NEXUS_AK_SOURCE")
if not ak_source or #ak_source == 0 then
    raise("NEXUS_AK_SOURCE must point to the patched AK source")
end

target("ak-fallible-module")
    set_kind("static")
    add_includedirs(ak_source)
    add_files("module-probe.cppm", {public = true})

target("ak-fallible-module-test")
    set_kind("binary")
    add_files("module-consumer.cpp")
    add_deps("ak-fallible-module")
    add_ldflags("-Wl,--wrap=malloc", {force = true})
