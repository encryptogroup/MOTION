message("!!!!! Building boost from sources. This can take a few minutes.")

include(ExternalProject)

set(MOTION_BUILD_BOOST_FROM_SOURCES ON)
set(Boost_URL "https://dl.bintray.com/boostorg/release/1.75.0/source/boost_1_75_0.tar.bz2")
set(Boost_URL_HASH_SHA256 "953db31e016db7bb207f11432bef7df100516eeb746843fa0486a222e3fd49cb")
set(Boost_INSTALL ${CMAKE_CURRENT_BINARY_DIR}/extern/boost)
set(Boost_LIB_DIR ${Boost_INSTALL}/lib)
set(Boost_INCLUDE_DIRS ${Boost_INSTALL}/include)

list(APPEND Boost_SANITIZER_FLAGS "")
if(MOTION_ENABLE_SANITIZERS)
    list(APPEND Boost_SANITIZER_FLAGS "context-impl=ucontext")
endif()

if (${CMAKE_BUILD_TYPE} STREQUAL "Release")
    set(Boost_BUILD_TYPE "release")
else ()
    set(Boost_BUILD_TYPE "debug")
endif ()

ExternalProject_Add(external_boost
        PREFIX boost
        URL ${Boost_URL}
        URL_HASH SHA256=${Boost_URL_HASH_SHA256}
        BUILD_IN_SOURCE 1
        CONFIGURE_COMMAND ./bootstrap.sh
        --with-libraries=context,fiber,log,filesystem,system,thread,program_options
        --prefix=<INSTALL_DIR>
        BUILD_COMMAND
        env -u CPATH -u C_INCLUDE_PATH ./b2 install link=static variant=${Boost_BUILD_TYPE} ${Boost_SANITIZER_FLAGS} threading=multi -j 10 define=BOOST_LOG_USE_NATIVE_SYSLOG define=BOOST_ERROR_CODE_HEADER_ONLY
        INSTALL_COMMAND ""
        INSTALL_DIR ${Boost_INSTALL}
        SOURCE_DIR ${Boost_INCLUDE_DIRS})

add_library(boost::context STATIC IMPORTED GLOBAL)
set_property(TARGET boost::context PROPERTY IMPORTED_LOCATION ${Boost_LIB_DIR}/libboost_context.a)
set_property(TARGET boost::context PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIRS})
add_dependencies(boost::context external_boost)
add_library(Boost::context ALIAS boost::context)

add_library(boost::fiber STATIC IMPORTED GLOBAL)
set_property(TARGET boost::fiber PROPERTY IMPORTED_LOCATION ${Boost_LIB_DIR}/libboost_fiber.a)
set_property(TARGET boost::fiber PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIRS})
add_dependencies(boost::fiber external_boost)
add_library(Boost::fiber ALIAS boost::fiber)

add_library(boost::log_setup SHARED IMPORTED GLOBAL)
set_property(TARGET boost::log_setup PROPERTY IMPORTED_LOCATION ${Boost_LIB_DIR}/libboost_log_setup.a)
set_property(TARGET boost::log_setup PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIRS})
add_dependencies(boost::log_setup external_boost)
add_library(Boost::log_setup ALIAS boost::log_setup)

add_library(boost::log SHARED IMPORTED GLOBAL)
set_property(TARGET boost::log PROPERTY IMPORTED_LOCATION ${Boost_LIB_DIR}/libboost_log.a)
set_property(TARGET boost::log PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIRS})
add_dependencies(boost::log external_boost)
add_library(Boost::log ALIAS boost::log)

add_library(boost::system STATIC IMPORTED GLOBAL)
set_property(TARGET boost::system PROPERTY IMPORTED_LOCATION ${Boost_LIB_DIR}/libboost_system.a)
set_property(TARGET boost::system PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIRS})
add_dependencies(boost::system external_boost)
add_library(Boost::system ALIAS boost::system)

add_library(boost::filesystem STATIC IMPORTED GLOBAL)
set_property(TARGET boost::filesystem PROPERTY IMPORTED_LOCATION ${Boost_LIB_DIR}/libboost_filesystem.a)
set_property(TARGET boost::filesystem PROPERTY INTERFACE_LINK_LIBRARIES boost::system)
set_property(TARGET boost::filesystem PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIRS})
add_dependencies(boost::filesystem external_boost)
add_library(Boost::filesystem ALIAS boost::filesystem)

add_library(boost::thread STATIC IMPORTED GLOBAL)
set_property(TARGET boost::thread PROPERTY IMPORTED_LOCATION ${Boost_LIB_DIR}/libboost_thread.a)
set_property(TARGET boost::thread PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIRS})
add_dependencies(boost::thread external_boost)
add_library(Boost::thread ALIAS boost::thread)

add_library(boost::program_options STATIC IMPORTED GLOBAL)
set_property(TARGET boost::program_options PROPERTY IMPORTED_LOCATION ${Boost_LIB_DIR}/libboost_program_options.a)
set_property(TARGET boost::program_options PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIRS})
add_dependencies(boost::program_options external_boost)
add_library(Boost::program_options ALIAS boost::program_options)
