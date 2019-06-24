add_executable(example_dummy example_dummy.cpp)

target_link_libraries(example_dummy
        ABYN::abyn
        )