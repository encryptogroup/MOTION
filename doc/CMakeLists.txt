find_package(Doxygen REQUIRED dot)
if (DOXYGEN_FOUND)
    set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile)

    execute_process(COMMAND echo COMMAND ${CMAKE_CXX_COMPILER} -Wp,-v -x c++ - -fsyntax-only ERROR_VARIABLE GXX_OUTPUT)
    set(ENV{GXX_OUTPUT} ${GXX_OUTPUT})
    execute_process(COMMAND echo ${GXX_OUTPUT} COMMAND grep "^\ " COMMAND sed "s#\ ##g" COMMAND tr "\n" " " OUTPUT_VARIABLE GXX_INCLUDES)

    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)

    message("Building docs")

    add_custom_target(motion_doc
            ALL
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            DEPENDS fbs-generation)
else (DOXYGEN_FOUND)
    message("Doxygen / Graphviz was not found")
endif (DOXYGEN_FOUND)