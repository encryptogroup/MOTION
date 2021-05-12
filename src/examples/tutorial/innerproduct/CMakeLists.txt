add_executable(innerproduct innerproduct_main.cpp common/innerproduct.cpp)

if (NOT MOTION_BUILD_BOOST_FROM_SOURCES)
    find_package(Boost
            COMPONENTS
            program_options
            REQUIRED)
endif ()

target_link_libraries(innerproduct
        MOTION::motion
        Boost::program_options
        )
