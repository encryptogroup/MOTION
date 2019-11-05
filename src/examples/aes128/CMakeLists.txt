add_executable(aes128 aes128_main.cpp common/aes128.cpp)

find_package(Boost 1.66.0
        COMPONENTS
        program_options
        REQUIRED)

target_compile_features(aes128 PRIVATE cxx_std_17)

target_link_libraries(aes128
        MOTION::motion
        ${Boost_LIBRARIES}
        )

target_compile_features(aes128 PRIVATE cxx_std_17)