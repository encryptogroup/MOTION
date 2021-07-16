add_executable(millionaires_problem millionaires_problem_main.cpp common/millionaires_problem.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(millionaires_problem
        MOTION::motion
        Boost::program_options
        )
