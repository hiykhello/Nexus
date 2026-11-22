cmake_minimum_required(VERSION 4.5 FATAL_ERROR)
project(nexus-desktop LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

option(NEXUS_DESKTOP_BUILD_UI "Build Slint v1.19.0 GUI executable" ON)
option(NEXUS_DESKTOP_BUILD_TESTS "Build C++26 desktop bridge unit tests" ON)
option(NEXUS_SLINT_FETCH "Fetch Slint v1.19.0 from source if no prebuilt Slint C++ SDK is found" OFF)

set(NEXUS_BRIDGE_IMPLS
    src/async_worker.cpp
    src/core_supervisor.cpp
    src/firewall_helper.cpp
    src/http_control.cpp
    src/profile_store.cpp
    src/service_installer.cpp
    src/share_link.cpp
    src/single_instance.cpp
    src/system_proxy.cpp
    src/tray_controller.cpp
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
            src/firewall_helper.cppm
            src/http_control.cppm
            src/ipc_client.cppm
            src/profile_store.cppm
            src/service_installer.cppm
            src/share_link.cppm
            src/single_instance.cppm
            src/system_proxy.cppm
            src/tray_controller.cppm
)
target_compile_features(nexus-desktop-bridge PUBLIC cxx_std_26)

if(WIN32)
    target_link_libraries(nexus-desktop-bridge PUBLIC wininet ws2_32 advapi32 shell32 user32)
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
    target_compile_features(nexus-desktop PRIVATE cxx_std_26)
    target_link_libraries(nexus-desktop PRIVATE nexus-desktop-bridge Slint::Slint)

    if(WIN32)
        set_target_properties(nexus-desktop PROPERTIES WIN32_EXECUTABLE TRUE)
    endif()
endif()

if(NEXUS_DESKTOP_BUILD_TESTS)
    enable_testing()
    add_executable(nexus-desktop-tests tests/bridge_test.cpp)
    target_compile_features(nexus-desktop-tests PRIVATE cxx_std_26)
    target_link_libraries(nexus-desktop-tests PRIVATE nexus-desktop-bridge)
    add_test(NAME nexus-desktop-tests COMMAND nexus-desktop-tests)
endif()
