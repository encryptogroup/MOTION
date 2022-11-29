# set HYCC_DIR to the path of the HyCC root directory
set(HYCC_DIR "../../../../HyCC")

if(NOT DEFINED HYCC_DIR OR NOT EXISTS ${HYCC_DIR})
  message( FATAL_ERROR "Error: HYCC_DIR ${HYCC_DIR} does not exist and needs to be set CMakeLists.txt in ${CMAKE_CURRENT_SOURCE_DIR}" )
endif()

link_directories(${HYCC_DIR}/src/libcircuit)

add_executable(aby-hycc main.cpp hycc_adapter.cpp circuit_converter.cpp)

target_include_directories(aby-hycc PUBLIC
  ${HYCC_DIR}/src/circuit-utils/include
  ${HYCC_DIR}/src
  ${HYCC_DIR}/src/cbmc/src
)

target_link_libraries(aby-hycc
  ABY::aby
  ENCRYPTO_utils::encrypto_utils
  circuit
)
