find_package(PkgConfig REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/src/abyncore)

add_executable(abyntest
        abyntest.cpp
        )

target_link_libraries(abyntest ABYN::abyn fmt::fmt ${GTEST_LIBRARIES} ${GTEST_LDFLAGS})