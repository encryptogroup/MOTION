add_executable(motion_benchmark conditional_fiber.cpp element_access_in_vector.cpp garbled_circuit.cpp)

target_link_libraries(motion_benchmark
        MOTION::motion
        benchmark::benchmark
        benchmark::benchmark_main
        )
