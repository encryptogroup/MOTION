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
        test_sp.cpp
        test_ot.cpp
        test_reusable_future.cpp
        )

target_compile_features(motiontest PRIVATE cxx_std_17)

target_link_libraries(motiontest PRIVATE
        MOTION::motion
        OpenMP::OpenMP_CXX
        gtest
        )
