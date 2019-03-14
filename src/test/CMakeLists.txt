find_package(PkgConfig REQUIRED)



add_executable(abyntest
        abyntest.cpp
        )


target_include_directories(abyntest PRIVATE
        ${PROJECT_SOURCE_DIR}/src/abyncore
        ${PROJECT_SOURCE_DIR}/extern/googletest/googletest/include)

target_link_libraries(abyntest ABYN::abyn fmt::fmt ${GTEST_LIBRARIES} ${GTEST_LDFLAGS})