add_executable(benchmark_liangzhao_signed_integer_operation benchmark_liangzhao_signed_integer_operation_main.cpp common/benchmark_liangzhao_signed_integer_operation.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(benchmark_liangzhao_signed_integer_operation
        MOTION::motion
        Boost::program_options
        )
