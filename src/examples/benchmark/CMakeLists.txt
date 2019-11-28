add_executable(benchmark benchmark_main.cpp common/benchmark.cpp)

find_package(Boost
        COMPONENTS
        program_options
        REQUIRED)

target_compile_features(benchmark PRIVATE cxx_std_17)

target_link_libraries(benchmark
        MOTION::motion
        Boost::program_options
        )

target_compile_features(benchmark PRIVATE cxx_std_17)