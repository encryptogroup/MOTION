add_executable(motiontest
        test_motion_main.cpp

        # test_aesni.cpp
        # test_agmw.cpp
        # test_astra.cpp
        # # test_base_ot.cpp # compile error
        # test_bgmw.cpp
        # test_bitmatrix.cpp
        # test_bitvector.cpp
        # test_bmr.cpp
        # test_boolean_algorithms.cpp
        # test_communication_layer.cpp
        # test_conversions.cpp
        # test_dummy_transport.cpp
        # test_garbled_circuit.cpp
        # # test_integer_operations.cpp # compile error
        # test_kk13_ot.cpp
        # test_kk13_ot_flavors.cpp
        # test_low_depth_reduce.cpp
        # test_misc.cpp
        # test_mt.cpp
        # test_ot.cpp
        # test_ot_flavors.cpp
        # test_reusable_future.cpp
        # test_rng.cpp
        # test_sb.cpp
        # # test_simdify_gate.cpp # compile error
        # test_sp.cpp
        # # test_subset_gate.cpp # compile error
        # test_tcp_transport.cpp
        # test_unsimdify_gate.cpp

        # test_unsigned_integer_operations_bgmw.cpp # test passed
        # test_unsigned_integer_operations_bmr.cpp # test passed
        # test_signed_integer_operations_bgmw.cpp # test passed
        # test_signed_integer_operations_bmr.cpp # test passed
        # test_floating_point_circuit_ABY_bgmw.cpp # test passed
        # test_floating_point_circuit_ABY_bmr.cpp # test passed
        # test_fixed_point_circuit_CBMC_bgmw.cpp # test passed
        # test_fixed_point_circuit_CBMC_bmr.cpp # test passed
        # test_basic_random_number_generation.cpp # test passed
        # test_invertbinarytree.cpp # test passed
        # test_geometricExp_discreteLaplace_discreteGaussian.cpp  
        # test_PrivaDA.cpp # test passed
        # test_gaussian_mechanism.cpp # test passed
        # test_discrete_laplace_mechanism_CKS.cpp
        # test_discrete_gaussian_mechanism_CKS.cpp
        # test_integer_scaling_laplace_mechanism.cpp
        # test_integer_scaling_gaussian_mechanism.cpp
)

target_link_libraries(motiontest PRIVATE
        MOTION::motion
        OpenMP::OpenMP_CXX
        gtest dl
)
