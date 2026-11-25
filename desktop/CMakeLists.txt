cmake_minimum_required(VERSION 4.5 FATAL_ERROR)
project(nexus-desktop LANGUAGES CXX)

if(MSVC)
    set(CMAKE_CXX_STANDARD 23)
else()
    set(CMAKE_CXX_STANDARD 26)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

option(NEXUS_DESKTOP_BUILD_UI "Build Slint v1.19.0 GUI executable" ON)
option(NEXUS_DESKTOP_BUILD_TESTS "Build C++26 desktop bridge unit tests" ON)
option(NEXUS_SLINT_FETCH "Fetch Slint v1.19.0 from source if no prebuilt Slint C++ SDK is found" OFF)

set(NEXUS_BRIDGE_IMPLS
    src/async_worker.cpp
    src/core_supervisor.cpp
    src/desktop_host_config.cpp
    src/firewall_helper.cpp
    src/http_control.cpp
    src/kdl_ops.cpp
    src/mini_json.cpp
    src/profile_store.cpp
    src/service_installer.cpp
    src/share_link.cpp
    src/single_instance.cpp
    src/system_proxy.cpp
    src/telemetry_store.cpp
    src/tray_controller.cpp
    src/tray_linux_sni.cpp
    src/tray_win32.cpp
    src/tun_helper_protocol.cpp
    src/tun_privilege.cpp
    src/ui_actions.cpp
    src/ui_prefs.cpp
    src/window_blur.cpp
    src/workspace_composer.cpp
    src/workspace_store.cpp
)
if(WIN32)
    list(APPEND NEXUS_BRIDGE_IMPLS src/ipc_client_win.cpp)
else()
    list(APPEND NEXUS_BRIDGE_IMPLS src/ipc_client_linux.cpp)
endif()

add_library(nexus-desktop-bridge STATIC ${NEXUS_BRIDGE_IMPLS})
target_sources(nexus-desktop-bridge
    PUBLIC
        FILE_SET CXX_MODULES FILES
            src/async_worker.cppm
            src/core_supervisor.cppm
            src/desktop_host_config.cppm
            src/firewall_helper.cppm
            src/http_control.cppm
            src/ipc_client.cppm
            src/kdl_ops.cppm
            src/mini_json.cppm
            src/profile_store.cppm
            src/service_installer.cppm
            src/share_link.cppm
            src/single_instance.cppm
            src/system_proxy.cppm
            src/telemetry_store.cppm
            src/tray_controller.cppm
            src/tun_helper_protocol.cppm
            src/tun_privilege.cppm
            src/ui_actions.cppm
            src/ui_prefs.cppm
            src/window_blur.cppm
            src/workspace_composer.cppm
            src/workspace_models.cppm
            src/workspace_store.cppm
)
if(MSVC)
    target_compile_features(nexus-desktop-bridge PUBLIC cxx_std_23)
    target_compile_options(nexus-desktop-bridge PUBLIC /utf-8)
else()
    target_compile_features(nexus-desktop-bridge PUBLIC cxx_std_26)
endif()

if(WIN32)
    target_compile_definitions(nexus-desktop-bridge PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN)
    target_link_libraries(nexus-desktop-bridge PUBLIC wininet ws2_32 advapi32 shell32 user32)

    add_executable(nexus-tun-helper src/tun_helper_win.cpp)
    if(MSVC)
        target_compile_features(nexus-tun-helper PRIVATE cxx_std_23)
    else()
        target_compile_features(nexus-tun-helper PRIVATE cxx_std_26)
    endif()
    target_link_libraries(nexus-tun-helper PRIVATE nexus-desktop-bridge)
elseif(APPLE)
    add_executable(nexus-tun-helper src/tun_helper_macos.cpp)
    target_compile_features(nexus-tun-helper PRIVATE cxx_std_26)
    target_link_libraries(nexus-tun-helper PRIVATE nexus-desktop-bridge)
elseif(UNIX)
    target_link_libraries(nexus-desktop-bridge PUBLIC ${CMAKE_DL_LIBS})
endif()

if(NEXUS_DESKTOP_BUILD_UI)
    find_package(Slint QUIET)
    if(NOT Slint_FOUND)
        if(NEXUS_SLINT_FETCH)
            include(FetchContent)
            FetchContent_Declare(
                Slint
                GIT_REPOSITORY https://github.com/slint-ui/slint.git
                GIT_TAG v1.19.0
                SOURCE_SUBDIR api/cpp
            )
            FetchContent_MakeAvailable(Slint)
        else()
            message(FATAL_ERROR
                "Slint v1.19.0 C++ SDK not found. Pass -DSlint_DIR=<path-to-Slint-cpp-1.19.0>, "
                "enable -DNEXUS_SLINT_FETCH=ON, or pass -DNEXUS_DESKTOP_BUILD_UI=OFF to build bridge/tests only.")
        endif()
    endif()

    add_executable(nexus-desktop src/main.cpp)
    slint_target_sources(nexus-desktop
        ui/app_window.slint
        NAMESPACE nexus_ui
    )
    if(MSVC)
        target_compile_features(nexus-desktop PRIVATE cxx_std_23)
    else()
        target_compile_features(nexus-desktop PRIVATE cxx_std_26)
    endif()
    target_link_options(nexus-desktop PRIVATE
        $<$<AND:$<NOT:$<CXX_COMPILER_ID:MSVC>>,$<NOT:$<PLATFORM_ID:Darwin>>,$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>>:-Wl,-s>
    )
    target_link_libraries(nexus-desktop PRIVATE nexus-desktop-bridge Slint::Slint)

    if(WIN32)
        set_target_properties(nexus-desktop PROPERTIES WIN32_EXECUTABLE TRUE)
    endif()
endif()

if(NEXUS_DESKTOP_BUILD_TESTS)
    enable_testing()
    add_executable(nexus-desktop-tests tests/bridge_test.cpp)
    if(MSVC)
        target_compile_features(nexus-desktop-tests PRIVATE cxx_std_23)
    else()
        target_compile_features(nexus-desktop-tests PRIVATE cxx_std_26)
    endif()
    target_link_libraries(nexus-desktop-tests PRIVATE nexus-desktop-bridge)
    add_test(NAME nexus-desktop-tests COMMAND nexus-desktop-tests)
    set_tests_properties(nexus-desktop-tests PROPERTIES ENVIRONMENT "NEXUS_DISABLE_NATIVE_TRAY=1")

    add_executable(nexus-desktop-ui-ops-tests tests/ui_ops_test.cpp)
    if(MSVC)
        target_compile_features(nexus-desktop-ui-ops-tests PRIVATE cxx_std_23)
    else()
        target_compile_features(nexus-desktop-ui-ops-tests PRIVATE cxx_std_26)
    endif()
    target_link_libraries(nexus-desktop-ui-ops-tests PRIVATE nexus-desktop-bridge)
    add_test(NAME nexus-desktop-ui-ops-tests COMMAND nexus-desktop-ui-ops-tests)

    add_executable(nexus-desktop-tray-tests tests/tray_test.cpp)
    if(MSVC)
        target_compile_features(nexus-desktop-tray-tests PRIVATE cxx_std_23)
    else()
        target_compile_features(nexus-desktop-tray-tests PRIVATE cxx_std_26)
    endif()
    target_link_libraries(nexus-desktop-tray-tests PRIVATE nexus-desktop-bridge)
    add_test(NAME nexus-desktop-tray-tests COMMAND nexus-desktop-tray-tests)
    set_tests_properties(nexus-desktop-tray-tests PROPERTIES ENVIRONMENT "NEXUS_DISABLE_NATIVE_TRAY=1")

    add_executable(nexus-desktop-tun-privilege-tests tests/tun_privilege_test.cpp)
    if(MSVC)
        target_compile_features(nexus-desktop-tun-privilege-tests PRIVATE cxx_std_23)
    else()
        target_compile_features(nexus-desktop-tun-privilege-tests PRIVATE cxx_std_26)
    endif()
    target_link_libraries(nexus-desktop-tun-privilege-tests PRIVATE nexus-desktop-bridge)
    add_test(NAME nexus-desktop-tun-privilege-tests COMMAND nexus-desktop-tun-privilege-tests)

    add_executable(nexus-desktop-workspace-tests tests/workspace_test.cpp)
    if(MSVC)
        target_compile_features(nexus-desktop-workspace-tests PRIVATE cxx_std_23)
    else()
        target_compile_features(nexus-desktop-workspace-tests PRIVATE cxx_std_26)
    endif()
    target_link_libraries(nexus-desktop-workspace-tests PRIVATE nexus-desktop-bridge)
    add_test(NAME nexus-desktop-workspace-tests COMMAND nexus-desktop-workspace-tests)
endif()
