cmake_minimum_required(VERSION 3.12)
cmake_policy(SET CMP0075 NEW)
project(MOTION LANGUAGES CXX)
set(MOTION_VERSION 0.01)

string(REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")

if (CMAKE_COMPILER_IS_GNUCXX AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
    message(FATAL_ERROR "MOTION requires at least g++-8")
endif ()

option(MOTION_BUILD_EXE "Build executables" OFF)
option(MOTION_BUILD_TESTS "Build tests" OFF)
option(MOTION_BUILD_DOC "Build documentation" OFF)
option(MOTION_LINK_TCMALLOC "Link against tcmalloc" OFF)
set(MOTION_USE_AVX OFF CACHE STRING "Use AVX/AVX2/AVX512/AVX512VAES instructions")
set_property(CACHE MOTION_USE_AVX PROPERTY STRINGS OFF AVX AVX2 AVX512 AVX512VAES)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(OpenMP REQUIRED)

# At least boost 1.75.0 is needed to use Boost::json.
set(MOTION_Boost_VERSION "1.75.0")
list(APPEND MOTION_Boost_COMPONENTS
	context
        fiber
        filesystem
        json
        log
        log_setup
        program_options
        system
        thread)

find_package(Boost QUIET ${MOTION_Boost_VERSION}
        COMPONENTS
        ${MOTION_Boost_COMPONENTS})
set(Boost_USE_STATIC_LIBS ON)

set(MOTION_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(MOTION_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(MOTION_EXTERN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/extern")

if ("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_CURRENT_SOURCE_DIR}")
    # Set build type to `Release` if non was specified:
    if (NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Release CACHE STRING
                "Choose the type of build, options are: None Debug Release"
                FORCE)
    endif (NOT CMAKE_BUILD_TYPE)

    message("BUILD TYPE: " ${CMAKE_BUILD_TYPE})
endif ()

if ("${CMAKE_BUILD_TYPE}" MATCHES "Debug" OR "${CMAKE_BUILD_TYPE}" MATCHES "RelWithDebInfo")
    set(MOTION_DEBUG "true")
else ()
    set(MOTION_DEBUG "false")
endif ()

if (Boost_FOUND)
    set(MOTION_BOOST_LOG_DYN_LINK ON)
else ()
    include(cmake/BuildBoostLocally.cmake)
endif ()

# Write built executables and libraries to bin/ and lib/, respectively.
if (NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin")
endif ()
if (NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")
endif ()
if (NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")
endif ()

find_package(fmt QUIET)
if (fmt_FOUND)
    message(STATUS "Found fmt")
elseif (NOT fmt_FOUND AND NOT TARGET fmt::fmt)
    message("fmt was not found: add fmt subdirectory")
    if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/fmt/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/fmt")
        execute_process(COMMAND git submodule update --init extern/fmt
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()
    # we use the header-only version of fmt
    # -> add `target_compile_definitions($TARGET PUBLIC FMT_HEADER_ONLY)` for
    # targets using fmt
    #set(FMT_TEST OFF CACHE BOOL "Enable building fmt tests" FORCE)
    #add_subdirectory(extern/fmt)
endif ()

set(FBS_DIR_FULL_PREFIX "${MOTION_ROOT_DIR}/fbs")
set(FBS_INCLUDE_PREFIX "${MOTION_ROOT_DIR}/src/motioncore/communication/fbs_headers")

find_package(Flatbuffers QUIET)
if (Flatbuffers_FOUND)
    message(STATUS "Found flatbuffers")
    if (WIN32)
        set(FLATBUFFERS_FLATC_EXECUTABLE "flatc.exe")
    else()
        set(FLATBUFFERS_FLATC_EXECUTABLE "flatc")
    endif()
elseif (NOT Flatbuffers_FOUND AND NOT TARGET flatbuffers::flatbuffers)
    message("flatbuffers was not found: add flatbuffers subdirectory")
    if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/flatbuffers/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/flatbuffers")
        execute_process(COMMAND git submodule update --init extern/flatbuffers
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()

    set(FLATBUFFERS_BUILD_FLATLIB OFF CACHE BOOL "Enable building flatlib" FORCE)
    set(FLATBUFFERS_BUILD_FLATHASH OFF CACHE BOOL "Disable building flathash" FORCE)
    set(FLATBUFFERS_BUILD_TESTS OFF CACHE BOOL "Disable building flatbuffers tests" FORCE)
    add_subdirectory(${PROJECT_SOURCE_DIR}/extern/flatbuffers
            ${CMAKE_CURRENT_BINARY_DIR}/flatbuffers-build)
    if (WIN32)
        set(FLATBUFFERS_FLATC_EXECUTABLE "${PROJECT_BINARY_DIR}/bin/flatc.exe")
    else()
        set(FLATBUFFERS_FLATC_EXECUTABLE "${PROJECT_BINARY_DIR}/bin/flatc")
    endif()
endif ()
add_subdirectory(fbs)

add_subdirectory(src/motioncore)

if (MOTION_BUILD_TESTS)
    find_package(GTest QUIET)
    if (GTest_Found)
        message(STATUS "Found GTest")
    elseif (NOT GTest_Found AND NOT TARGET gtest::gtest)
        if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/googletest/CMakeLists.txt")
            find_package(Git REQUIRED)
            message("initialize Git submodule: extern/googletest")
            execute_process(COMMAND git submodule update --init extern/googletest
                    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
        endif ()

        set(BUILD_GMOCK OFF CACHE BOOL "Disable building gmock" FORCE)
        add_subdirectory(extern/googletest)
        add_subdirectory(src/test)
    endif ()
endif (MOTION_BUILD_TESTS)

if (MOTION_BUILD_EXE)
    add_subdirectory(src/examples)
endif (MOTION_BUILD_EXE)

if (MOTION_BUILD_DOC)
    add_subdirectory(doc)
endif (MOTION_BUILD_DOC)
