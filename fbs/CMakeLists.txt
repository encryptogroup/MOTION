set(FBS_NAMES output_message hello_message message) #add the names of the new fbs files here
set(FBS_INCLUDE_PREFIX "${CMAKE_SOURCE_DIR}/src/abyncore/communication/fbs_headers")
set(FLATC_FULL_PATH "${FLATC_DIR}/flatc")

set(GENERATED_FILES "")

foreach (FILE ${FBS_NAMES})
    set(THIS_FBS "${FBS_DIR_FULL_PREFIX}/${FILE}.fbs")
    set(THIS_H "${FBS_INCLUDE_PREFIX}/${FILE}_generated.h")
    if ((NOT ${THIS_H}) OR (${THIS_FBS} IS_NEWER_THAN ${THIS_H}))
        add_custom_command(OUTPUT ${THIS_H}
                COMMAND ${FLATC_DIR}/flatc --cpp -o ${FBS_INCLUDE_PREFIX} ${THIS_FBS}
                DEPENDS ${THIS_FBS})
    endif ()
    list(APPEND GENERATED_FILES ${THIS_H})
endforeach ()

add_custom_target(fbs-generation ALL DEPENDS flatc ${GENERATED_FILES})
