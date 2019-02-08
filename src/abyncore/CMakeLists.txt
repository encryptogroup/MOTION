include_directories(${PROJECT_SOURCE_DIR}/src/abyncore)

add_library(abyn
        abynparty/abynparty.cpp
        abynparty/abynbackend.cpp
        gate/gate.cpp
        share/share.cpp
        wire/wire.cpp
        utility/party.cpp
        utility/abynconfiguration.cpp
        utility/logger.cpp
        utility/datastorage.cpp
        crypto/aesrandomnessgenerator.cpp
        communication/partycommunicationhandler.cpp
        )
add_library(ABYN::abyn ALIAS abyn)

target_compile_features(abyn PUBLIC cxx_std_17)
target_compile_options(abyn PRIVATE "-Wall" "-Wextra")

add_dependencies(abyn fbs-generation)

target_include_directories(abyn
        PUBLIC
        $<INSTALL_INTERFACE:include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
        ${Boost_INCLUDE_DIRS}
        )

target_link_libraries(abyn
        PRIVATE stdc++fs
        PUBLIC OTExtension::otextension
        PUBLIC ENCRYPTO_utils::encrypto_utils
        PUBLIC GMP::GMP
        PUBLIC Threads::Threads
        PUBLIC ${Boost_LIBRARIES}
        PRIVATE flatbuffers
        PRIVATE fmt::fmt-header-only
        )

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


