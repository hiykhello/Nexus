package("nexus-corosio")
    set_homepage("https://github.com/cppalliance/corosio")
    set_description("Pinned Boost.Corosio I/O core")
    set_license("BSL-1.0")
    add_urls(os.getenv("NEXUS_COROSIO_SOURCE") or "https://github.com/cppalliance/corosio.git")
    add_versions("0.3.3", "70adbd5aff90569aac588e78a717fecbd5b7dedc")
    add_patches("0.3.3", path.join(os.scriptdir(), "thread_local_modules.patch"), "b1d7a479d8e34c9e7701f54dfa9e62ec425efc300a58cdcfbefa3f2b5f8fbdbf")
    add_deps("nexus-capy 0.2.2", {system = false})
    add_configs("uring", {description = "Use system liburing for io_uring", default = false, type = "boolean"})
    add_links("boost_corosio")
    add_defines("BOOST_COROSIO_NO_LIB", "BOOST_COROSIO_STATIC_LINK")
    on_load(function (package)
        if package:config("uring") then
            assert(package:is_plat("linux"), "io_uring is only supported on Linux")
            package:add("deps", "liburing >=2.5", {system = true})
            package:add("defines", "BOOST_COROSIO_HAVE_LIBURING=1")
        else
            package:add("defines", "BOOST_COROSIO_HAVE_LIBURING=0")
        end
    end)
    on_install(function (package)
        import("package.tools.cmake")
        local capy = package:dep("nexus-capy")
        local inject = path.absolute("nexus-capy-inject.cmake")
        local capydir = path.translate(capy:installdir(), "/")
        local extra = package:config("uring") and 'find_package(PkgConfig REQUIRED)\npkg_check_modules(NEXUS_URING REQUIRED "liburing>=2.5")\n' or ''
        io.writefile(inject, 'find_package(Threads REQUIRED)\nfind_package(boost_capy CONFIG REQUIRED PATHS "' .. capydir .. '" NO_DEFAULT_PATH)\nadd_library(boost_capy ALIAS Boost::capy)\n' .. extra)
        -- This upstream target has no module units; GCC 16 ICEs scanning the uring sources.
        local configs = {"-DBUILD_SHARED_LIBS=OFF", "-DBUILD_TESTING=OFF", "-DCMAKE_CXX_STANDARD=26", "-DCMAKE_CXX_SCAN_FOR_MODULES=OFF",
            "-DBOOST_COROSIO_BUILD_TESTS=OFF", "-DBOOST_COROSIO_BUILD_EXAMPLES=OFF", "-DBOOST_COROSIO_BUILD_BENCH=OFF",
            "-DCMAKE_DISABLE_FIND_PACKAGE_OpenSSL=TRUE", "-DCMAKE_DISABLE_FIND_PACKAGE_WolfSSL=TRUE",
            "-DCMAKE_PROJECT_INCLUDE=" .. inject}
        if not package:config("uring") then
            table.insert(configs, "-DCMAKE_DISABLE_FIND_PACKAGE_liburing=TRUE")
        end
        cmake.install(package, configs)
        os.cp("LICENSE_1_0.txt", package:installdir("share/licenses/nexus-corosio"))
    end)
    on_test(function (package)
        assert(package:has_cxxincludes("boost/corosio/io_context.hpp", {configs = {languages = "c++26"}}))
    end)
package_end()
