add_executable(test_example test_example_main.cpp)

target_link_libraries(test_example
        ABYN::abyn
        ENCRYPTO_utils::encrypto_utils
        fmt::fmt
        ${SANITIZE_ADDRESS_LINK_OPT}
        )