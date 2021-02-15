add_executable(example_template example_template_main.cpp common/example_template.cpp)

find_package(Boost
        COMPONENTS
        program_options
        REQUIRED)

target_link_libraries(example_template
        MOTION::motion
        Boost::program_options
        )
