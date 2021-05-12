add_executable(mult3 mult3_main.cpp common/mult3.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(mult3
        MOTION::motion
        Boost::program_options
        )
