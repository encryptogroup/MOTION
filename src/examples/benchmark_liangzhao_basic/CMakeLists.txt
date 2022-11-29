add_executable(benchmark_liangzhao_basic benchmark_liangzhao_basic_main.cpp common/benchmark_liangzhao_basic.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(benchmark_liangzhao_basic
        MOTION::motion
        Boost::program_options
        )
