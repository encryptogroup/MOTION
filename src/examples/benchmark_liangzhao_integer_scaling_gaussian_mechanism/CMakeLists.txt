add_executable(benchmark_liangzhao_integer_scaling_gaussian_mechanism benchmark_liangzhao_integer_scaling_gaussian_mechanism_main.cpp common/benchmark_liangzhao_integer_scaling_gaussian_mechanism.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(benchmark_liangzhao_integer_scaling_gaussian_mechanism
        MOTION::motion
        Boost::program_options
        )
