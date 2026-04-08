cmake_minimum_required(VERSION 3.20)

project(hpcap LANGUAGES CXX)

include(FetchContent)

option(HPCAP_BUILD_EXAMPLES "Build example programs" ON)
option(HPCAP_BUILD_TESTS "Build unit tests" ON)
option(HPCAP_ENABLE_ZLIB "Enable gzip support with zlib" OFF)
option(HPCAP_ENABLE_BZIP2 "Enable bzip2 support" OFF)
option(HPCAP_ENABLE_LZMA "Enable lzma/xz support" OFF)

add_library(hpcap INTERFACE)
add_library(hpcap::hpcap ALIAS hpcap)

target_compile_features(hpcap INTERFACE cxx_std_20)
target_include_directories(hpcap
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

if(HPCAP_ENABLE_ZLIB)
    find_package(ZLIB REQUIRED)
    target_compile_definitions(hpcap INTERFACE HAS_ZLIB)
    target_link_libraries(hpcap INTERFACE ZLIB::ZLIB)
endif()

if(HPCAP_ENABLE_BZIP2)
    find_package(BZip2 REQUIRED)
    target_compile_definitions(hpcap INTERFACE HAS_BZIP2)
    target_link_libraries(hpcap INTERFACE BZip2::BZip2)
endif()

if(HPCAP_ENABLE_LZMA)
    find_package(LibLZMA REQUIRED)
    target_compile_definitions(hpcap INTERFACE HAS_LZMA)
    target_link_libraries(hpcap INTERFACE LibLZMA::LibLZMA)
endif()

if(HPCAP_BUILD_EXAMPLES)
    add_executable(pcap_runner examples/pcap_runner.cpp)
    target_link_libraries(pcap_runner PRIVATE hpcap::hpcap)
endif()

if(HPCAP_BUILD_TESTS)
    enable_testing()
    include(GoogleTest)

    find_package(GTest CONFIG QUIET)
    if(NOT GTest_FOUND)
        FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.zip
        )
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
    endif()

    add_executable(frame_tests tests/frame_tests.cpp)
    target_link_libraries(frame_tests PRIVATE hpcap::hpcap GTest::gtest_main)

    add_executable(pcap_tests tests/pcap_tests.cpp)
    target_link_libraries(pcap_tests PRIVATE hpcap::hpcap GTest::gtest_main)

    gtest_discover_tests(frame_tests)
    gtest_discover_tests(pcap_tests)

    if(HPCAP_ENABLE_ZLIB)
        add_executable(pcap_roundtrip_tests tests/pcap_roundtrip_tests.cpp)
        target_link_libraries(pcap_roundtrip_tests PRIVATE hpcap::hpcap GTest::gtest_main)

        gtest_discover_tests(pcap_roundtrip_tests)
    endif()
endif()
