add_executable(benchmark benchmark_main.cpp common/benchmark.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(benchmark
        MOTION::motion
        Boost::program_options
        )
