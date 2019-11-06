add_executable(example_template example_template_main.cpp common/example_template.cpp)

find_package(Boost
        COMPONENTS
        program_options
        REQUIRED)

target_compile_features(example_template PRIVATE cxx_std_17)

target_link_libraries(example_template
        MOTION::motion
        Boost::program_options
        )

target_compile_features(example_template PRIVATE cxx_std_17)