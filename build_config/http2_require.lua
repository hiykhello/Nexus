option("http2")
    set_default(false)
    set_showmenu(true)
    set_description("Enable experimental pinned libnghttp2 HTTP/2 core")
option_end()
if has_config("http2") then
    add_requires("nexus-nghttp2 1.70.0", {system = false})
end
