cmake_minimum_required(VERSION 3.12)
project(ABYN LANGUAGES CXX)
set(ABYN_VERSION 1.00)

option(ABYN_BUILD_EXE "Build executables" ON)
option(ABYN_BUILD_TESTS "Build tests" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package(GMP REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

ADD_DEFINITIONS(-DBOOST_LOG_DYN_LINK)
find_package(Boost
        COMPONENTS
        log
        log_setup
        filesystem
        system
        REQUIRED)
set(Boost_USE_STATIC_LIBS ON)

find_package(OpenMP REQUIRED)

if ("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}") #set flags if we are in the top level CMakeLists
    set(CMAKE_VECTORIZATION_FLAGS "-maes -msse2 -msse4.1 -msse4.2 -mpclmul -mavx -mavx2")
    if (ABYN_AVX512)
        set(CMAKE_VECTORIZATION_FLAGS "${CMAKE_VECTORIZATION_FLAGS} -mavx512f")
    endif ()

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_VECTORIZATION_FLAGS} ${OpenMP_CXX_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ffunction-sections -march=native -Wall")

    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)

    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

    # Set build type to `Release` if non was specified:
    if (NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Release CACHE STRING
                "Choose the type of build, options are: None Debug Release"
                FORCE)
    endif (NOT CMAKE_BUILD_TYPE)

    message("BUILD TYPE: " ${CMAKE_BUILD_TYPE})

    if ("${CMAKE_BUILD_TYPE}" MATCHES "Debug")
        message("CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE} is debug")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_DEBUG}")
        set(CMAKE_XCODE_GENERATE_SCHEME ON)
        set(CMAKE_XCODE_SCHEME_ADDRESS_SANITIZER ON)
        set(CMAKE_XCODE_SCHEME_ADDRESS_SANITIZER_USE_AFTER_RETURN ON)
    else ()
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_RELEASE}")
    endif ()
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
        @ONLY
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

set(CMAKE_CXX_STANDARD 17)

find_package(ENCRYPTO_utils QUIET)
if (ENCRYPTO_utils_FOUND)
    message(STATUS "Found ENCRYPTO_utils")
elseif (NOT ENCRYPTO_utils_FOUND AND NOT TARGET ENCRYPTO_utils::encrypto_utils)
    message("ENCRYPTO_utils was not found: add ENCRYPTO_utils subdirectory")
    if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/ENCRYPTO_utils/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/ENCRYPTO_utils")
        execute_process(COMMAND git submodule update --init extern/ENCRYPTO_utils
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()
    add_subdirectory(extern/ENCRYPTO_utils)
endif ()

find_package(OTExtension QUIET)
if (OTExtension_FOUND)
    message(STATUS "Found OTExtension")
elseif (NOT OTExtension_FOUND AND NOT TARGET OTExtension::otextension)
    message("OTExtension was not found: add OTExtension subdirectory")
    if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/OTExtension/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/OTExtension")
        execute_process(COMMAND git submodule update --init extern/OTExtension
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()
    add_subdirectory(extern/OTExtension)
endif ()

set(BUILD_SHARED_LIBS TRUE)
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
    add_subdirectory(extern/fmt)
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

    option(FLATBUFFERS_BUILD_FLATHASH OFF)
    option(FLATBUFFERS_BUILD_TESTS OFF)
    set(FLATC_DIR "${PROJECT_BINARY_DIR}/bin")
    set(FBS_DIR_FULL_PREFIX "${PROJECT_SOURCE_DIR}/fbs")
    add_subdirectory(${FLATBUFFERS_SRC_DIR}
            extern/flatbuffers)
    add_subdirectory(fbs)
endif ()

include_directories(extern)
include_directories(extern/flatbuffers/include)
include_directories(src/abyncore)

add_subdirectory(src/abyncore)

if (ABYN_BUILD_TESTS)
    add_subdirectory(src/test)
endif (ABYN_BUILD_TESTS)

if (ABYN_BUILD_EXE)
    add_subdirectory(extern/googletest EXCLUDE_FROM_ALL)
    add_subdirectory(src/examples)
endif (ABYN_BUILD_EXE)
