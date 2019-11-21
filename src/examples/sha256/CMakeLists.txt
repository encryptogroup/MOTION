add_executable(sha256 sha256_main.cpp common/sha256.cpp)

find_package(Boost
        COMPONENTS
        program_options
        REQUIRED)

target_compile_features(sha256 PRIVATE cxx_std_17)

target_link_libraries(sha256
        MOTION::motion
        Boost::program_options
        )

target_compile_features(sha256 PRIVATE cxx_std_17)