add_executable(benchmark_primitive_operations
        benchmark_primitive_operations_main.cpp
        common/benchmark_primitive_operations.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(benchmark_primitive_operations
        MOTION::motion
        Boost::program_options
        )
