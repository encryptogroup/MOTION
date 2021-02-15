add_executable(benchmark_providers benchmark_providers_main.cpp common/benchmark_providers.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(benchmark_providers
        MOTION::motion
        Boost::program_options
        )
