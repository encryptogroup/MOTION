add_executable(example_template example_template_main.cpp common/example_template.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(example_template
        MOTION::motion
        Boost::program_options
        )
