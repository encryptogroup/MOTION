add_executable(aes128 aes128_main.cpp common/aes128.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(aes128
        MOTION::motion
        Boost::program_options
        )
