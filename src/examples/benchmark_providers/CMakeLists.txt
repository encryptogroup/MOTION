add_executable(benchmark_providers benchmark_providers_main.cpp common/benchmark_providers.cpp)

find_package(Boost
        COMPONENTS
        program_options
        REQUIRED)

target_compile_features(benchmark_providers PRIVATE cxx_std_17)

target_link_libraries(benchmark_providers
        MOTION::motion
        Boost::program_options
        )

target_compile_features(benchmark_providers PRIVATE cxx_std_17)