find_package(PkgConfig REQUIRED)
pkg_search_module(GTEST REQUIRED gtest_main)
find_package(GTest REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/src/abyncore)

add_executable(abyntest
        abyntest.cpp
        )

target_compile_options(abyntest PRIVATE "-Wall" "-Wextra")
target_link_libraries(abyntest ABYN::abyn ENCRYPTO_utils::encrypto_utils fmt::fmt  ${GTEST_LIBRARIES} ${GTEST_LDFLAGS})
target_compile_options(abyntest PUBLIC ${GTEST_CFLAGS} ${CMAKE_THREAD_LIBS_INIT})