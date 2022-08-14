add_executable(benchmark_integer_scaling_mechanism benchmark_integer_scaling_mechanism_main.cpp common/benchmark_integer_scaling_mechanism.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(benchmark_integer_scaling_mechanism
        MOTION::motion
        Boost::program_options
        )
