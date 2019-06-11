add_executable(abyntest
        test_abyn_main.cpp
        test_abyn.cpp
        test_bitvector.cpp
        )

target_include_directories(abyntest PRIVATE
        ${PROJECT_SOURCE_DIR}/extern/googletest/googletest/include)

target_link_libraries(abyntest PUBLIC
        ABYN::abyn
        fmt::fmt
        gtest
        )
