add_executable(benchmark_integers benchmark_integers_main.cpp common/benchmark_integers.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(benchmark_integers
        MOTION::motion
        Boost::program_options
        )
