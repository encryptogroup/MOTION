get_filename_component(MOTION_CMAKE_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)

list(APPEND CMAKE_MODULE_PATH "${MOTION_CMAKE_DIR}")

include(CMakeFindDependencyMacro)

find_dependency(Boost ${MOTION_Boost_VERSION} QUIET REQUIRED COMPONENTS ${MOTION_Boost_COMPONENTS})
find_dependency(flatbuffers)
find_dependency(fmt)
find_dependency(Threads)

if(NOT TARGET MOTION::motion)
    include("${MOTION_CMAKE_DIR}/MOTIONTargets.cmake")
endif()
