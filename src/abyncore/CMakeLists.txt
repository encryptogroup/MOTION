add_library(abyn
        base/backend.cpp
        base/configuration.cpp
        base/party.cpp
        base/register.cpp
        communication/context.cpp
        communication/handler.cpp
        communication/hello_message.cpp
        communication/message.cpp
        communication/output_message.cpp
        crypto/aes_randomness_generator.cpp
        gate/gate.cpp
        share/share.cpp
        utility/bit_vector.cpp
        utility/data_storage.cpp
        utility/helpers.cpp
        utility/logger.cpp
        wire/wire.cpp
        )
add_library(ABYN::abyn ALIAS abyn)

target_compile_definitions(abyn PRIVATE BOOST_LOG_DYN_LINK=1 PUBLIC OMP_NESTED=1)

target_compile_features(abyn PRIVATE cxx_std_17)
target_compile_options(abyn PRIVATE "-Wall" "-Wextra")
target_compile_options(abyn PRIVATE ${OMIT_FRAME_POINTER_COMP_OPT} ${SANITIZE_ADDRESS_COMP_OPT})

add_custom_target(
        abyn_config ALL DEPENDS
        "${PROJECT_SOURCE_DIR}/src/abyncore/utility/config.h.in"
)

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


