cmake_minimum_required(VERSION 3.22)
project(MOTION_helper)

set(CMAKE_CXX_STANDARD 20)

add_executable(MOTION_helper main.cpp floating_point_operation.h floating_point_operation.cpp fixed_point_operation.h fixed_point_operation.cpp fix64_k64_f16.h fix64_k64_f16.cpp fix64_k64_f33.h fix64_k64_f48.h fix128.h export_to_csv.h snapping_mechanism.h snapping_mechanism.cpp dp_mechanism_helper.cpp dp_mechanism_helper.h integer_scaling_mechanism.cpp integer_scaling_mechanism.h discrete_gaussian_mechanism.h discrete_gaussian_mechanism.cpp test_fix64.cpp test_fix64.h float32.h float32.cpp float64.h float64.cpp)
