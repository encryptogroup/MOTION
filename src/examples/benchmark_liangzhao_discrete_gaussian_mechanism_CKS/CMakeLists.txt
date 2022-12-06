add_executable(benchmark_liangzhao_discrete_gaussian_mechanism_CKS benchmark_liangzhao_discrete_gaussian_mechanism_CKS_main.cpp common/benchmark_liangzhao_discrete_gaussian_mechanism_CKS.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(benchmark_liangzhao_discrete_gaussian_mechanism_CKS
        MOTION::motion
        Boost::program_options
        )
