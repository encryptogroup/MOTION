add_executable(benchmark_liangzhao_dp_mechanism_PrivaDA benchmark_liangzhao_dp_mechanism_PrivaDA_main.cpp common/benchmark_liangzhao_dp_mechanism_PrivaDA.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(benchmark_liangzhao_dp_mechanism_PrivaDA
        MOTION::motion
        Boost::program_options
        )
