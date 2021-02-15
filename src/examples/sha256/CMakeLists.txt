add_executable(sha256 sha256_main.cpp common/sha256.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(sha256
        MOTION::motion
        Boost::program_options
        )
