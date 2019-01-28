cmake_minimum_required(VERSION 3.12)
project(ABYN LANGUAGES CXX)

option(ABYN_BUILD_EXE "Build executables" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package(GMP        REQUIRED)
find_package(Threads    REQUIRED)
find_package(OpenSSL    REQUIRED)

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
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)



# Set build type to `Release` if non was specified:
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING
            "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
            FORCE)
endif(NOT CMAKE_BUILD_TYPE)


# Write built executables and libraries to bin/ and lib/, respectively.
if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin")
endif()
if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")
endif()
if(NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")
endif()

set(CMAKE_CXX_STANDARD 17)

find_package(ENCRYPTO_utils QUIET)
if(ENCRYPTO_utils_FOUND)
    message(STATUS "Found ENCRYPTO_utils")
elseif(NOT ENCRYPTO_utils_FOUND AND NOT TARGET ENCRYPTO_utils::encrypto_utils)
    message("ENCRYPTO_utils was not found: add ENCRYPTO_utils subdirectory")
    if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/ENCRYPTO_utils/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/ENCRYPTO_utils")
        execute_process(COMMAND git submodule update --init extern/ENCRYPTO_utils
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif()
    add_subdirectory(extern/ENCRYPTO_utils)
endif()

find_package(OTExtension QUIET)
if(OTExtension_FOUND)
    message(STATUS "Found OTExtension")
elseif (NOT OTExtension_FOUND AND NOT TARGET OTExtension::otextension)
    message("OTExtension was not found: add OTExtension subdirectory")
    if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/OTExtension/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/OTExtension")
        execute_process(COMMAND git submodule update --init extern/OTExtension
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif()
    add_subdirectory(extern/OTExtension)
endif()

set(BUILD_SHARED_LIBS TRUE)
find_package(fmt QUIET)
if(fmt_FOUND)
    message(STATUS "Found fmt")
elseif (NOT fmt_FOUND AND NOT TARGET fmt::fmt)
    message("fmt was not found: add fmt subdirectory")
    if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/fmt/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/fmt")
        execute_process(COMMAND git submodule update --init extern/fmt
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif()
    add_subdirectory(extern/fmt)
endif()

find_package(flatbuffers QUIET)
if(flatbuffers_FOUND)
    message(STATUS "Found flatbuffers")
elseif (NOT flatbuffers_FOUND AND NOT TARGET flatbuffers::flatbuffers)
    message("flatbuffers was not found: add flatbuffers subdirectory")
    if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/flatbuffers/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/flatbuffers")
        execute_process(COMMAND git submodule update --init extern/flatbuffers
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif()

    option(FLATBUFFERS_BUILD_TESTS FALSE)
    add_subdirectory(${FLATBUFFERS_SRC_DIR}
                 extern/flatbuffers)
endif()

include_directories(extern)
include_directories(extern/flatbuffers/include)
include_directories(src/abyncore)

add_subdirectory(src/abyncore)


if(ABYN_BUILD_EXE)
    add_subdirectory(src/test)
    add_subdirectory(src/examples)
endif(ABYN_BUILD_EXE)
