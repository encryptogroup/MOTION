add_executable(benchmark_fixed_point_operation benchmark_fixed_point_operation_main.cpp common/benchmark_fixed_point_operation.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(benchmark_fixed_point_operation
        MOTION::motion
        Boost::program_options
        )
