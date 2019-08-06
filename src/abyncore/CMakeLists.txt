add_library(abyn
        base/backend.cpp
        base/configuration.cpp
        base/party.cpp
        base/register.cpp
        communication/base_ot_message.cpp
        communication/context.cpp
        communication/handler.cpp
        communication/hello_message.cpp
        communication/message.cpp
        communication/output_message.cpp
        crypto/aes_randomness_generator.cpp
        crypto/base_ots/ot_hl17.cpp
        crypto/curve25519/mycurve25519.cpp
        gate/gate.cpp
        gate/boolean_gmw_gate.cpp
        share/boolean_gmw_share.cpp
        share/share.cpp
        share/share_wrapper.cpp
        utility/bit_matrix.cpp
        utility/bit_vector.cpp
        utility/condition.cpp
        utility/data_storage.cpp
        utility/helpers.cpp
        utility/logger.cpp
        wire/boolean_gmw_wire.cpp
        wire/wire.cpp
        )
add_library(ABYN::abyn ALIAS abyn)


if (ABYN_AVX512)
    set(ABYN_AVX512_FLAG "-mavx512f")
endif ()

set_property(TARGET abyn PROPERTY POSITION_INDEPENDENT_CODE ON)

target_compile_definitions(abyn PRIVATE BOOST_LOG_DYN_LINK=1 PUBLIC OMP_NESTED=1)

# there is a strange bug that Party::Reset() sometimes results in a segfault in the next Party::Run
# this only happens in the Release mode and even not in RelWithDebInfo which makes it hard to find the bug
# TODO: fix

#if ("${CMAKE_BUILD_TYPE}" MATCHES "RelWithDebInfo")
#    list(APPEND ABYN_EXTRA_FLAGS
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


target_compile_features(abyn PRIVATE cxx_std_17)
target_compile_options(abyn PRIVATE
        ${ABYN_EXTRA_FLAGS}
        -Wall -Wextra
        -pedantic -ansi
        -maes -msse2 -msse4.1 -msse4.2 -mpclmul -mavx -mavx2
        -ffunction-sections -march=native
        -fvect-cost-model=unlimited
        ${ABYN_AVX512_FLAG})

add_custom_target(
        abyn_config ALL DEPENDS
        "${PROJECT_SOURCE_DIR}/src/abyncore/utility/config.h.in"
)

if (ABYN_COMPILATION_TIME_DEBUGGING)
    set_property(TARGET abyn PROPERTY RULE_LAUNCH_COMPILE "${CMAKE_COMMAND} -E time")
endif ()

add_dependencies(abyn fbs-generation abyn_config)

target_include_directories(abyn PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/abyncore>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/extern>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/extern/fmt/include>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/extern/flatbuffers/include>
        ${Boost_INCLUDE_DIRS}
        )

target_link_libraries(abyn
        PUBLIC ${Boost_LIBRARIES}
        PUBLIC OpenMP::OpenMP_CXX
        PRIVATE Threads::Threads
        PRIVATE OpenSSL::Crypto
        PRIVATE OpenSSL::SSL
        )

if (${SANITIZE_ADDRESS_LINK_OPT})
    target_link_libraries(abyn PUBLIC ${SANITIZE_ADDRESS_LINK_OPT})
endif ()

install(TARGETS abyn
        EXPORT "${PROJECT_NAME}Targets"
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        INCLUDES DESTINATION lib
        )

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        DESTINATION include
        FILES_MATCHING PATTERN "*.h"
        )

export(TARGETS abyn NAMESPACE "${PROJECT_NAME}::" FILE "${PROJECT_NAME}Targets.cmake")
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


