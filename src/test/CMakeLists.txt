include_directories(${PROJECT_SOURCE_DIR}/src/abyncore)


#add_executable(myTest src/test/abyntest.cpp)
#target_link_libraries(myTest ${GTEST_LIBRARIES} ${GTEST_LDFLAGS})
#target_compile_options(myTest PUBLIC ${GTEST_CFLAGS} ${CMAKE_THREAD_LIBS_INIT})

add_executable(abyntest
        abyntest.cpp
        )
target_compile_options(abyntest PRIVATE "-Wall" "-Wextra")
target_link_libraries(abyntest ABYN::abyn ENCRYPTO_utils::encrypto_utils ${GTEST_LIBRARIES} ${GTEST_LDFLAGS})
target_compile_options(abyntest PUBLIC ${GTEST_CFLAGS} ${CMAKE_THREAD_LIBS_INIT})