add_subdirectory(aes128)
add_subdirectory(benchmark_integers)
# add_subdirectory(benchmark_primitive_operations)
# add_subdirectory(benchmark_providers)
# add_subdirectory(example_template)
# add_subdirectory(sha256)
# add_subdirectory(tutorial/crosstabs)
# add_subdirectory(tutorial/innerproduct)
# add_subdirectory(tutorial/mult3)
# add_subdirectory(millionaires_problem)

# =================================================================
# added by Liang Zhao
add_subdirectory(benchmark_liangzhao_unsigned_integer_operation)
add_subdirectory(benchmark_liangzhao_signed_integer_operation)
add_subdirectory(benchmark_liangzhao_floating_point_operation)
add_subdirectory(benchmark_liangzhao_fixed_point_operation)

add_subdirectory(benchmark_liangzhao_dp_mechanism_PrivaDA)
add_subdirectory(benchmark_liangzhao_gaussian_mechanism_CrypTen)
add_subdirectory(benchmark_liangzhao_snapping_mechanism)
add_subdirectory(benchmark_liangzhao_discrete_laplace_mechanism_CKS)
add_subdirectory(benchmark_liangzhao_discrete_gaussian_mechanism_CKS)
add_subdirectory(benchmark_liangzhao_integer_scaling_laplace_mechanism)
add_subdirectory(benchmark_liangzhao_integer_scaling_gaussian_mechanism)

# add_subdirectory(benchmark_liangzhao_basic) # need to implement garbled_circuit conversion function
# add_subdirectory(benchmark_liangzhao_arithmetic_gmw_operation)

# # =================================================================
# add_subdirectory(benchmark_liangzhao_integer_scaling_mechanism)