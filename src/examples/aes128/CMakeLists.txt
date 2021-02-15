add_executable(aes128 aes128_main.cpp common/aes128.cpp)

find_package(Boost
        COMPONENTS
        program_options
        REQUIRED)

target_link_libraries(aes128
        MOTION::motion
        Boost::program_options
        )
