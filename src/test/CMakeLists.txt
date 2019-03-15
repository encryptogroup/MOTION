add_executable(abyntest
        abyntest.cpp
        )

target_include_directories(abyntest PRIVATE
        ${PROJECT_SOURCE_DIR}/extern/googletest/googletest/include)

target_link_libraries(abyntest PUBLIC
        ABYN::abyn
        fmt::fmt
        gtest)
