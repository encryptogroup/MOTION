add_library(motion
        algorithm/algorithm_description.cpp
        algorithm/boolean_algorithms.cpp
        algorithm/low_depth_reduce.h
        base/backend.cpp
        base/configuration.cpp
        base/motion_base_provider.cpp
        base/party.cpp
        base/register.cpp
        communication/communication_layer.cpp
        communication/dummy_transport.cpp
        communication/garbled_circuit_message.cpp
        communication/hello_message.cpp
        communication/message.cpp
        communication/message_manager.cpp
        communication/tcp_transport.cpp
        communication/transport.cpp
        executor/gate_executor.cpp
        multiplication_triple/mt_provider.cpp
        multiplication_triple/sb_provider.cpp
        multiplication_triple/sp_provider.cpp
        oblivious_transfer/base_ots/base_ot_provider.cpp
        oblivious_transfer/base_ots/ot_hl17.cpp
        oblivious_transfer/1_out_of_n/kk13_ot_flavors.cpp
        oblivious_transfer/1_out_of_n/kk13_ot_provider.cpp
        oblivious_transfer/ot_flavors.cpp
        oblivious_transfer/ot_provider.cpp
        primitives/aes/aesni_primitives.cpp
        primitives/blake2b.cpp
        primitives/curve25519/mycurve25519.cpp
        primitives/pseudo_random_generator.cpp
        primitives/sharing_randomness_generator.cpp
        primitives/random/aes128_ctr_rng.cpp
        primitives/random/openssl_rng.cpp
        protocols/arithmetic_gmw/arithmetic_gmw_gate.cpp
        protocols/arithmetic_gmw/arithmetic_gmw_share.cpp
        protocols/arithmetic_gmw/arithmetic_gmw_wire.cpp
        protocols/astra/astra_gate.cpp
        protocols/astra/astra_wire.cpp
        protocols/astra/astra_share.cpp
        protocols/bmr/bmr_gate.cpp
        protocols/bmr/bmr_provider.cpp
        protocols/bmr/bmr_share.cpp
        protocols/bmr/bmr_wire.cpp
        protocols/boolean_gmw/boolean_gmw_gate.cpp
        protocols/boolean_gmw/boolean_gmw_share.cpp
        protocols/boolean_gmw/boolean_gmw_wire.cpp
        protocols/constant/constant_gate.cpp
        protocols/constant/constant_share.cpp
        protocols/constant/constant_wire.cpp
        protocols/conversion/conversion_gate.cpp
        protocols/data_management/simdify_gate.cpp
        protocols/data_management/subset_gate.cpp
        protocols/data_management/unsimdify_gate.cpp
        protocols/garbled_circuit/garbled_circuit_gate.cpp
        protocols/garbled_circuit/garbled_circuit_provider.cpp
        protocols/garbled_circuit/garbled_circuit_share.cpp
        protocols/garbled_circuit/garbled_circuit_wire.cpp
        protocols/gate.cpp
        protocols/share.cpp
        protocols/share_wrapper.cpp
        protocols/wire.cpp
        secure_type/secure_signed_integer.cpp
        secure_type/secure_unsigned_integer.cpp
        statistics/analysis.cpp
        statistics/run_time_statistics.cpp
        utility/bit_matrix.cpp
        utility/bit_vector.cpp
        utility/block.cpp
        utility/condition.cpp
        utility/fiber_waitable.cpp
        utility/fiber_thread_pool/fiber_thread_pool.cpp
        utility/fiber_thread_pool/pooled_work_stealing.cpp
        utility/helpers.cpp
        utility/logger.cpp
        utility/runtime_info.cpp
        utility/thread.cpp
        )
add_library(MOTION::motion ALIAS motion)


# Add version information to library
file(TOUCH "${CMAKE_CURRENT_BINARY_DIR}/version.cpp")
target_sources(motion PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/version.cpp")
add_custom_target(motion_version
        COMMAND "${CMAKE_COMMAND}"
        "-DVERSION_CPP_IN:FILEPATH=${CMAKE_CURRENT_SOURCE_DIR}/utility/version.cpp.in"
        "-P" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.cmake"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/utility/version.cpp.in"
        BYPRODUCTS "${CMAKE_CURRENT_BINARY_DIR}/version.cpp.new"
        COMMENT "gather information about git repository and generating version.cpp")
add_dependencies(motion motion_version)


# -fvect-cost-model flag is not supported by clang(++)
if (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(MOTION_VECT_COST_MODEL_GCC_FLAG "-fvect-cost-model=unlimited")
endif ()

set_property(TARGET motion PROPERTY POSITION_INDEPENDENT_CODE ON)

if (MOTION_BOOST_LOG_DYN_LINK)
    target_compile_definitions(motion PUBLIC OMP_NESTED=1 BOOST_LOG_DYN_LINK=1)
else ()
    target_compile_definitions(motion PUBLIC OMP_NESTED=1)
endif ()
#target_compile_options(motion PUBLIC "-fno-omit-frame-pointer" "-fsanitize=address")
#target_link_options(motion PUBLIC "-fno-omit-frame-pointer" "-fsanitize=address")
#target_compile_options(motion PUBLIC "-fsanitize=thread")
#target_link_options(motion PUBLIC "-fsanitize=thread")

# there is a strange bug that Party::Reset() sometimes results in a segfault in the next Party::Run
# this only happens in the Release mode and even not in RelWithDebInfo which makes it hard to find the bug
# TODO: fix

#if ("${CMAKE_BUILD_TYPE}" MATCHES "RelWithDebInfo")
#    list(APPEND MOTION_EXTRA_FLAGS
#            -fgcse-after-reload
#            -finline-functions
#            -fipa-cp-clone
#            -floop-interchange
#            -floop-unroll-and-jam
#            -fpeel-loops
#            -fpredictive-commoning
#            -fsplit-paths
#            -ftree-loop-distribute-patterns
#            -ftree-loop-distribution
#            -ftree-loop-vectorize
#            -ftree-partial-pre
#            -ftree-slp-vectorize
#            -funswitch-loops
#            -fvect-cost-model
#            )
#endif ()

target_compile_features(motion PUBLIC cxx_std_20)
target_compile_options(motion PRIVATE
        ${MOTION_EXTRA_FLAGS}
        -Wall -Wextra
        -pedantic
        -maes -msse2 -msse4.1 -msse4.2 -mpclmul
        -ffunction-sections -march=native -ffast-math
        ${MOTION_VECT_COST_MODEL_GCC_FLAG}
        )

if (WIN32)
    target_link_libraries(motion PUBLIC wsock32 ws2_32)
    target_include_directories(motion PUBLIC
            $<INSTALL_INTERFACE:include>
            $<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIR}>)
endif ()

# Prevent undefined references to `__log2_finite' and `__exp2_finite' when
# compiling with clang.
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(motion PRIVATE -fno-builtin)
endif ()

set(MOTION_ALIGNMENT 16)
if (MOTION_USE_AVX)
    # at least AVX
    target_compile_options(motion PRIVATE -mavx)
    target_compile_definitions(motion PRIVATE MOTION_AVX)
    add_compile_definitions(MOTION_AVX)
    set(MOTION_ALIGNMENT 32)
    if (NOT MOTION_USE_AVX STREQUAL "AVX")
        # at least AVX2
        target_compile_options(motion PRIVATE -mavx2)
        target_compile_definitions(motion PRIVATE MOTION_AVX2)
        if (NOT MOTION_USE_AVX STREQUAL "AVX2")
            # AVX512, based on what's available on a Skylake-X CPU
            target_compile_options(motion PRIVATE -mavx512f -mavx512dq -mavx512cd -mavx512bw -mavx512vl)
            target_compile_definitions(motion PRIVATE MOTION_AVX512)
            set(MOTION_ALIGNMENT 64)
            if (NOT MOTION_USE_AVX STREQUAL "AVX512")
                # AVX512 with VAES (and potentially whatever else we need beyond basic Cascade Lake Extensions)
                target_compile_options(motion PRIVATE -mvaes)
                target_compile_definitions(motion PRIVATE MOTION_AVX512_VAES)
            endif ()
        endif ()
    endif ()
endif ()

configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/utility/config.h.in
        ${CMAKE_CURRENT_SOURCE_DIR}/utility/config.h
        ESCAPE_QUOTES @ONLY
)

add_custom_target(
        motion_config ALL DEPENDS
        "${MOTION_ROOT_DIR}/src/motioncore/utility/config.h.in"
)

if (MOTION_COMPILATION_TIME_DEBUGGING)
    set_property(TARGET motion PROPERTY RULE_LAUNCH_COMPILE "${CMAKE_COMMAND} -E time")
endif ()

add_dependencies(motion fbs-generation motion_config)

target_include_directories(motion PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/>
        $<BUILD_INTERFACE:${MOTION_ROOT_DIR}/src/motioncore>
        $<BUILD_INTERFACE:${MOTION_ROOT_DIR}/extern>
        $<BUILD_INTERFACE:${MOTION_ROOT_DIR}/extern/fmt/include>
        $<BUILD_INTERFACE:${MOTION_ROOT_DIR}/extern/flatbuffers/include>
        $<BUILD_INTERFACE:${Boost_INCLUDE_DIRS}>
        )

target_compile_definitions(motion PUBLIC FMT_HEADER_ONLY BOOST_ERROR_CODE_HEADER_ONLY)

target_link_libraries(motion
        PRIVATE
        Boost::context
        Boost::fiber
        Boost::log_setup
        Boost::log
        Boost::filesystem
        Boost::system
        Boost::thread
        OpenMP::OpenMP_CXX
        Threads::Threads
        OpenSSL::Crypto
        OpenSSL::SSL
        PUBLIC
        Boost::json
        )

if (MOTION_LINK_TCMALLOC)
	find_library(tcmalloc_minimal REQUIRED
		NAMES tcmalloc_minimal libtcmalloc_minimal
		PATHS ${TCMALLOC_ROOT}/lib
		)
	target_link_libraries(motion PRIVATE tcmalloc_minimal)
endif ()

install(TARGETS motion
        EXPORT "${PROJECT_NAME}Targets"
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        INCLUDES DESTINATION lib
        )

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        DESTINATION include
        FILES_MATCHING PATTERN "*.h"
        )

export(TARGETS motion NAMESPACE "${PROJECT_NAME}::" FILE "${PROJECT_NAME}Targets.cmake")
install(EXPORT "${PROJECT_NAME}Targets"
        NAMESPACE "${PROJECT_NAME}::"
        DESTINATION "lib/cmake/${PROJECT_NAME}"
        )

include(CMakePackageConfigHelpers)

configure_package_config_file("${PROJECT_SOURCE_DIR}/cmake/${PROJECT_NAME}Config.cmake.in"
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
        INSTALL_DESTINATION "lib/cmake/${PROJECT_NAME}"
        )

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
        DESTINATION "lib/cmake/${PROJECT_NAME}"
        )
