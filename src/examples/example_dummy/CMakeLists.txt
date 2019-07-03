add_executable(example_dummy example_dummy.cpp)

target_link_libraries(example_dummy
        ABYN::abyn
        )

target_compile_features(example_dummy PRIVATE cxx_std_17)