add_executable(abyntest
        abyntest.cpp
        )

target_include_directories(abyntest PRIVATE
        ${PROJECT_SOURCE_DIR}/extern/googletest/googletest/include)

target_link_libraries(abyntest PUBLIC
        ABYN::abyn
        fmt::fmt
        gtest)

#target_link_libraries(abyntest ABYN::abyn fmt::fmt ${GTEST_LIBRARIES} ${GTEST_LDFLAGS})
#target_compile_options(abyntest PUBLIC ${GTEST_CFLAGS} ${CMAKE_THREAD_LIBS_INIT})