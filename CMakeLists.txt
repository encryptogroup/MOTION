cmake_minimum_required(VERSION 3.12)
cmake_policy(SET CMP0075 NEW)
project(ABYN LANGUAGES CXX)
set(ABYN_VERSION 0.01)


if (CMAKE_COMPILER_IS_GNUCXX AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
    message(FATAL_ERROR "ENCRYPTO_utils require at least g++-8")
endif ()

option(ABYN_BUILD_EXE "Build executables" OFF)
option(ABYN_BUILD_TESTS "Build tests" OFF)
option(ABYN_BUILD_DOC "Build documentation" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(GMP REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(OpenMP REQUIRED)

find_package(Boost 1.66.0
        COMPONENTS
        log
        log_setup
        filesystem
        system
        REQUIRED)
set(Boost_USE_STATIC_LIBS ON)

set(ABYN_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(ABYN_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(ABYN_EXTERN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/extern")


if ("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_CURRENT_BINARY_DIR}")
    # Set build type to `Release` if non was specified:
    if (NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Release CACHE STRING
                "Choose the type of build, options are: None Debug Release"
                FORCE)
    endif (NOT CMAKE_BUILD_TYPE)

    message("BUILD TYPE: " ${CMAKE_BUILD_TYPE})
endif ()

if ("${CMAKE_BUILD_TYPE}" MATCHES "Debug")
    set(ABYN_DEBUG "true")
else ()
    set(ABYN_DEBUG "false")
endif ()

configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/src/abyncore/utility/config.h.in
        ${CMAKE_CURRENT_SOURCE_DIR}/src/abyncore/utility/config.h
        ESCAPE_QUOTES
)

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
    add_definitions(-DFMT_HEADER_ONLY=TRUE)
    #set(FMT_TEST OFF CACHE BOOL "Enable building fmt tests" FORCE)
    #add_subdirectory(extern/fmt)
endif ()

find_package(flatbuffers QUIET)
if (flatbuffers_FOUND)
    message(STATUS "Found flatbuffers")
elseif (NOT flatbuffers_FOUND AND NOT TARGET flatbuffers::flatbuffers)
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
    set(FLATC_DIR "${PROJECT_BINARY_DIR}/bin")
    set(FBS_DIR_FULL_PREFIX "${PROJECT_SOURCE_DIR}/fbs")
    add_subdirectory(${PROJECT_SOURCE_DIR}/extern/flatbuffers
            ${CMAKE_CURRENT_BINARY_DIR}/flatbuffers-build)
    add_subdirectory(fbs)
endif ()
add_subdirectory(src/abyncore)

if (ABYN_BUILD_TESTS)
    if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/googletest/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/googletest")
        execute_process(COMMAND git submodule update --init extern/googletest
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()

    set(BUILD_GMOCK OFF CACHE BOOL "Disable building gmock" FORCE)
    add_subdirectory(extern/googletest)
    add_subdirectory(src/test)
endif (ABYN_BUILD_TESTS)

if (ABYN_BUILD_EXE)
    add_subdirectory(src/examples)
endif (ABYN_BUILD_EXE)

if (ABYN_BUILD_DOC)
    add_subdirectory(docs)
endif (ABYN_BUILD_DOC)