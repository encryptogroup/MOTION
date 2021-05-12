add_executable(crosstabs crosstabs_main.cpp common/crosstabs.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(crosstabs
        MOTION::motion
        Boost::program_options
        )
