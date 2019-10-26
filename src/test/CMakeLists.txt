add_executable(motiontest
        test_bitmatrix.cpp
        test_bitvector.cpp
        test_bmr.cpp
        test_conversions.cpp
        test_integer_operations.cpp
        test_misc.cpp
        test_motion.cpp
        test_motion_main.cpp
        test_mt.cpp
        test_ot.cpp
        )

target_compile_features(motiontest PRIVATE cxx_std_17)

target_include_directories(motiontest PRIVATE
        ${PROJECT_SOURCE_DIR}/extern/googletest/googletest/include)

target_link_libraries(motiontest PRIVATE
        MOTION::motion
        gtest
        )