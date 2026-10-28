package("nexus-nghttp2")
    set_homepage("https://github.com/nghttp2/nghttp2")
    set_description("Pinned libnghttp2 HTTP/2 protocol core")
    set_license("MIT")
    add_urls("https://github.com/nghttp2/nghttp2/releases/download/v1.70.0/nghttp2-1.70.0.tar.xz")
    add_versions("1.70.0", "e05cb1388eaca3830aded4ccf20044b6e1ac1a61411dcca11b0437c4285c8bc2")
    add_links("nghttp2")
    add_defines("NGHTTP2_STATICLIB")
    if is_plat("linux") then add_syslinks("pthread") end

    on_install(function (package)
        import("package.tools.cmake")
        local configs = {
            "-DENABLE_LIB_ONLY=ON",
            "-DENABLE_APP=OFF",
            "-DENABLE_EXAMPLES=OFF",
            "-DENABLE_HPACK_TOOLS=OFF",
            "-DENABLE_DOC=OFF",
            "-DENABLE_FAILMALLOC=OFF",
            "-DBUILD_SHARED_LIBS=OFF",
            "-DBUILD_STATIC_LIBS=ON",
            "-DBUILD_TESTING=OFF",
            "-DWITH_LIBXML2=OFF",
            "-DWITH_JEMALLOC=OFF",
            "-DCMAKE_DISABLE_FIND_PACKAGE_OpenSSL=TRUE",
            "-DCMAKE_DISABLE_FIND_PACKAGE_Libngtcp2=TRUE",
            "-DCMAKE_DISABLE_FIND_PACKAGE_Libnghttp3=TRUE",
            "-DCMAKE_DISABLE_FIND_PACKAGE_Libevent=TRUE",
            "-DCMAKE_DISABLE_FIND_PACKAGE_Jansson=TRUE",
            "-DCMAKE_DISABLE_FIND_PACKAGE_Systemd=TRUE",
            "-DCMAKE_DISABLE_FIND_PACKAGE_LibXml2=TRUE",
            "-DCMAKE_DISABLE_FIND_PACKAGE_Jemalloc=TRUE"
        }
        cmake.install(package, configs)
        os.cp("COPYING", package:installdir("share/licenses/nexus-nghttp2"))
    end)

    on_test(function (package)
        assert(package:has_cincludes("nghttp2/nghttp2.h"))
    end)
package_end()
