add_executable(abyntest
        test_abyn_main.cpp
        test_abyn.cpp
        test_bitvector.cpp
        test_misc.cpp
        )

target_include_directories(abyntest PRIVATE
        ${PROJECT_SOURCE_DIR}/extern/googletest/googletest/include)

target_link_libraries(abyntest PRIVATE
        ABYN::abyn
        gtest
        )
