add_executable(benchmark_liangzhao_gaussian_mechanism_CrypTen benchmark_liangzhao_gaussian_mechanism_CrypTen_main.cpp common/benchmark_liangzhao_gaussian_mechanism_CrypTen.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(benchmark_liangzhao_gaussian_mechanism_CrypTen
        MOTION::motion
        Boost::program_options
        )
