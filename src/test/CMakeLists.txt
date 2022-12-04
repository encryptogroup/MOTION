add_executable(motiontest
        test_motion_main.cpp

        # following tests without comments are successful
        # test_aesni.cpp # test passed

        # test_agmw.cpp # ! secure_signed_integer compile error, rest test passed
        # test_astra.cpp # test passed

        # test_base_ot.cpp # ! compiler error
        # test_bmr.cpp # test passed

        # test_bgmw.cpp # ! secure_signed_integer compile error, rest test passed
        # test_bitmatrix.cpp # test passed
        # test_bitvector.cpp # test passed
        # test_boolean_algorithms.cpp # test passed
        # test_communication_layer.cpp # test passed
        # test_conversions.cpp # test passed
        # test_dummy_transport.cpp # test passed
        # test_garbled_circuit.cpp # test passed
        # test_integer_operations.cpp # test passed
        # test_kk13_ot.cpp # test passed
        # test_kk13_ot_flavors.cpp # test passed
        # test_low_depth_reduce.cpp # test passed
        # test_misc.cpp # test passed
        # test_mt.cpp # test passed
        # test_ot.cpp # test passed
        # test_ot_flavors.cpp # test passed, but need to compile with test_ot.cpp together
        # test_sp.cpp # test passed
        # test_sb.cpp # test passed
        # test_reusable_future.cpp # test passed
        # test_rng.cpp # test passed
        # test_simdify_gate.cpp # test passed
        # test_subset_gate.cpp # test passed
        # test_tcp_transport.cpp # test passed
        # test_unsimdify_gate.cpp # test passed

        # =================================================================
        # liangzhao tests

        # test_liangzhao_mux_xcotmul.cpp # test passed

        # test_liangzhao_unsigned_integer_operations_bgmw.cpp # test passed, need intensive test, edge case test
        # test_liangzhao_unsigned_integer_operations_bmr.cpp # test passed, need intensive test, edge case test
        # test_liangzhao_unsigned_integer_operations_gc.cpp # test passed, need intensive test, edge case test

        # test_liangzhao_signed_integer_operations_bgmw.cpp # test passed, need intensive test, edge case test
        # test_liangzhao_signed_integer_operations_bmr.cpp # test passed, need intensive test, edge case test
        # test_liangzhao_signed_integer_operations_gc.cpp # test passed, need intensive test, edge case test
        # test_liangzhao_floating_point_circuit_ABY_bgmw.cpp # test passed, need intensive test, edge case test
        # test_liangzhao_floating_point_circuit_ABY_bmr.cpp # test passed, need intensive test, edge case test
        # test_liangzhao_floating_point_circuit_ABY_gc.cpp # test passed, need intensive test, edge case test

        # test_liangzhao_fixed_point_circuit_CBMC_bgmw.cpp # ! test passed, need intensive test, edge case test, cos circuit not available
        # test_liangzhao_fixed_point_circuit_CBMC_bmr.cpp # ! need test, log2_p1045 (.stat not available) and cos circuit not available
        # test_liangzhao_fixed_point_circuit_CBMC_gc.cpp # ! need test, log2_p1045 (.stat not available) and cos circuit not available

        # test_liangzhao_debug.cpp # only for debugging purposes

        # test_ot.cpp # test passed
        # test_liangzhao_ot_flavors.cpp # test passed, but need to compile with test_ot.cpp together

        # test_sp.cpp # test passed
        # test_liangzhao_sp.cpp # test passed

        # test_sb.cpp # test passed
        # test_liangzhao_sb.cpp # test passed

        # test_liangzhao_agmw.cpp # test passed

        # test_liangzhao_edaBit.cpp # test passed

        # test_liangzhao_EQ_EQZ_LTBits_LTC_LTS_LTZ.cpp # not tested

        # test_liangzhao_invertbinarytree.cpp # not tested

        # test_garbled_circuit.cpp # test passed

        # test_liangzhao_conversions.cpp
        # test_liangzhao_conversions_garbled_circuit.cpp # test passed

        # test_liangzhao_simdify_gate_garbled_circuit.cpp # test passed
        # test_liangzhao_subset_gate_garbled_circuit.cpp # test passed
        # test_liangzhao_unsimdify_gate_garbled_circuit.cpp # test passed

        # test_liangzhao_random_integer_algorithm.cpp # test passed
        # test_liangzhao_simple_geometric.cpp # test passed
        # test_liangzhao_uniformly_sampling.cpp # test passed

        # testing for naive algorithms
        # test_liangzhao_geometricExp_naive.cpp # test passed
        # test_liangzhao_discreteLaplace_naive.cpp # test passed
        # test_liangzhao_discreteGaussian_naive.cpp # test passed
        # test_liangzhao_symmericalBinomial_naive.cpp # test passed

        # testing for optimized algorithms
        # test_liangzhao_geometricExp_optimized.cpp # test passed
        # test_liangzhao_discreteLaplace_optimized.cpp # test passed
        # test_liangzhao_discreteGaussian_optimized.cpp # test passed
        # test_liangzhao_symmericalBinomial_optimized.cpp # test passed

        test_liangzhao_dp_mechanism_EKMPP.cpp # testing
)

target_link_libraries(motiontest PRIVATE
        MOTION::motion
        OpenMP::OpenMP_CXX
        gtest dl
)
