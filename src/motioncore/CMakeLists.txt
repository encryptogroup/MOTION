add_library(motion
        base/backend.cpp
        base/configuration.cpp
        base/party.cpp
        base/register.cpp
        communication/base_ot_message.cpp
        communication/bmr_message.cpp
        communication/context.cpp
        communication/handler.cpp
        communication/hello_message.cpp
        communication/message.cpp
        communication/ot_extension_message.cpp
        communication/output_message.cpp
        crypto/sharing_randomness_generator.cpp
        crypto/blake2b.cpp
        crypto/pseudo_random_generator.cpp
        crypto/base_ots/ot_hl17.cpp
        crypto/curve25519/mycurve25519.cpp
        crypto/multiplication_triple/mt_provider.cpp
        crypto/oblivious_transfer/ot_provider.cpp
        gate/bmr_gate.cpp
        gate/boolean_gmw_gate.cpp
        gate/gate.cpp
        share/bmr_share.cpp
        share/boolean_gmw_share.cpp
        share/share.cpp
        share/share_wrapper.cpp
        utility/bit_matrix.cpp
        utility/bit_vector.cpp
        utility/bristol_parser.cpp
        utility/condition.cpp
        utility/data_storage.cpp
        utility/helpers.cpp
        utility/logger.cpp
        wire/bmr_wire.cpp
        wire/boolean_gmw_wire.cpp
        wire/wire.cpp
        )
add_library(MOTION::motion ALIAS motion)


# -fvect-cost-model flag is not supported by clang(++)
if (NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    set(MOTION_VECT_COST_MODEL_GCC_FLAG "-fvect-cost-model=unlimited")
endif ()

set_property(TARGET motion PROPERTY POSITION_INDEPENDENT_CODE ON)

target_compile_definitions(motion PRIVATE BOOST_LOG_DYN_LINK=1 PUBLIC OMP_NESTED=1)
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


target_compile_features(motion PRIVATE cxx_std_17)
target_compile_options(motion PRIVATE
        ${MOTION_EXTRA_FLAGS}
        -Wall -Wextra
        -pedantic -ansi
        -maes -msse2 -msse4.1 -msse4.2 -mpclmul
        -ffunction-sections -march=native -ffast-math
        ${MOTION_VECT_COST_MODEL_GCC_FLAG}
        )

if (MOTION_USE_AVX)
    target_compile_options(motion PRIVATE -mavx)
    if (NOT MOTION_USE_AVX STREQUAL "AVX")
        target_compile_options(motion PRIVATE -mavx2)
        if (NOT MOTION_USE_AVX STREQUAL "AVX2")
            target_compile_options(motion PRIVATE -mavx512f)
        endif ()
    endif ()
endif ()

add_custom_target(
        motion_config ALL DEPENDS
        "${PROJECT_SOURCE_DIR}/src/motioncore/utility/config.h.in"
)

if (MOTION_COMPILATION_TIME_DEBUGGING)
    set_property(TARGET motion PROPERTY RULE_LAUNCH_COMPILE "${CMAKE_COMMAND} -E time")
endif ()

add_dependencies(motion fbs-generation motion_config)

target_include_directories(motion PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/motioncore>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/extern>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/extern/fmt/include>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/extern/flatbuffers/include>
        ${Boost_INCLUDE_DIRS}
        )

target_link_libraries(motion
        PUBLIC ${Boost_LIBRARIES}
        PUBLIC OpenMP::OpenMP_CXX
        PRIVATE Threads::Threads
        PRIVATE OpenSSL::Crypto
        PRIVATE OpenSSL::SSL
        )

if (${SANITIZE_ADDRESS_LINK_OPT})
    target_link_libraries(motion PUBLIC ${SANITIZE_ADDRESS_LINK_OPT})
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
