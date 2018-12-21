cmake_minimum_required(VERSION 3.12)
project(ABY-N LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package(GMP REQUIRED)
find_package(Threads REQUIRED)
find_package(Boost REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_search_module(GTEST REQUIRED gtest_main)
find_package(GTest REQUIRED)

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

find_package(cryptoTools QUIET)
if(cryptoTools_FOUND)
    message(STATUS "Found cryptoTools")
elseif(NOT cryptoTools_FOUND AND NOT TARGET cryptoTools::cryptotools)
    message("cryptoTools was not found: add cryptoTools subdirectory")
    if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/cryptoTools/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/cryptoTools")
        execute_process(COMMAND git submodule update --init extern/cryptoTools
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif()
    add_subdirectory(extern/cryptoTools)
endif()

#find_package(OTExtension QUIET)
#if(OTExtension_FOUND)
#    message(STATUS "Found OTExtension")
#elseif (NOT OTExtension_FOUND AND NOT TARGET OTExtension::otextension)
#    message("OTExtension was not found: add OTExtension subdirectory")
#    if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/OTExtension/CMakeLists.txt")
#        find_package(Git REQUIRED)
#        message("initialize Git submodule: extern/OTExtension")
#        execute_process(COMMAND git submodule update --init extern/OTExtension
#                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
#    endif()
#    add_subdirectory(extern/OTExtension)
#endif()

include_directories(utility)
include_directories(share)
include_directories(gate)
include_directories(.)

set(SOURCE_FILES main.cpp share/share.h utility/typedefs.h wire/wire.h wire/wire.cpp gate/gate.h gate/gate.cpp abyn.h)
add_executable(ABY-N ${SOURCE_FILES})

add_executable(myTest test/test.cpp)
target_link_libraries(myTest ${GTEST_LIBRARIES} ${GTEST_LDFLAGS})
target_compile_options(myTest PUBLIC ${GTEST_CFLAGS} ${CMAKE_THREAD_LIBS_INIT})
