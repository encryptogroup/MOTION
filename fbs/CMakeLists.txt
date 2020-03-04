file(GLOB FBS_NAMES "${FBS_DIR_FULL_PREFIX}/*.fbs")
#set(FBS_NAMES output_message hello_message message base_ot) #add the names of the new fbs files here

set(GENERATED_FILES "")

foreach (FILE ${FBS_NAMES})
    set(THIS_FBS "${FILE}")
    string(REGEX MATCH "[A-Za-z0-9_]+\\.fbs" THIS_H ${THIS_FBS})
    string(REGEX MATCH "^[A-Za-z0-9_]+" THIS_H ${THIS_H})
    set(THIS_H "${THIS_H}_generated.h")
    if ((NOT ${FBS_INCLUDE_PREFIX}/${THIS_H}) OR (${THIS_FBS} IS_NEWER_THAN ${FBS_INCLUDE_PREFIX}/${THIS_H}))
        add_custom_command(OUTPUT "${FBS_INCLUDE_PREFIX}/${THIS_H}"
                COMMAND ${FLATBUFFERS_FLATC_EXECUTABLE} --cpp --scoped-enums -o ${FBS_INCLUDE_PREFIX} ${THIS_FBS}
                DEPENDS ${THIS_FBS})
    endif ()
    list(APPEND GENERATED_FILES "${FBS_INCLUDE_PREFIX}/${THIS_H}")
endforeach ()

if(Flatbuffers_FOUND)
    add_custom_target(fbs-generation ALL DEPENDS ${GENERATED_FILES}) #flatc is already there
else()
    add_custom_target(fbs-generation ALL DEPENDS flatc ${GENERATED_FILES})
endif()
