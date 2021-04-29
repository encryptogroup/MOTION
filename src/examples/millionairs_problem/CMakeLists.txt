add_executable(millionairs_problem millionairs_problem.cpp common/millionair.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(millionairs_problem
        MOTION::motion
        Boost::program_options
        )
