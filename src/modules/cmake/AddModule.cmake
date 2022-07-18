# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function(add_module DIRECTORY)
    # Check for module.json file in the root of the directory
    file(READ ${DIRECTORY}/module.json MODULE_JSON)

    # Parse the module.json file (name, description, version, versionInfo, components, lifetime, userAccount, model)
    string(JSON MODULE_NAME GET ${MODULE_JSON} name)
    string(JSON MODULE_DESCRIPTION GET ${MODULE_JSON} description)
    string(JSON MODULE_VERSION GET ${MODULE_JSON} version)
    string(JSON MODULE_VERSION_INFO GET ${MODULE_JSON} versionInfo)
    string(JSON MODULE_COMPONENTS GET ${MODULE_JSON} components)
    string(JSON MODULE_LIFETIME GET ${MODULE_JSON} lifetime)
    string(JSON MODULE_USER_ACCOUNT GET ${MODULE_JSON} userAccount)
    string(JSON MODULE_MODEL GET ${MODULE_JSON} model)

    # TODO: validate the module.json file and MmiGetInfo()

    message("Generating module: ${MODULE_NAME} ${MODULE_VERSION} ${MODULE_COMPONENTS}")

    string(TOLOWER ${MODULE_NAME} MODULE_NAME_LOWER)
    string(TOUPPER ${MODULE_NAME} MODULE_NAME_UPPER)

    project(${DIRECTORY})

    set(target ${DIRECTORY}lib)
    file(GLOB SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/${DIRECTORY}/src/*)

    add_library(${TARGET} STATIC ${SRC_FILES})

    target_link_libraries(${TARGET} PRIVATE logging commonutils)
    target_include_directories(${TARGET}
        PUBLIC
            ${MODULES_INC_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}/${DIRECTORY}/src)

    target_compile_options(${TARGET} PUBLIC -fsigned-char)
    set_target_properties(${TARGET} PROPERTIES POSITION_INDEPENDENT_CODE ON)

    configure_file(
        ${MODULES_TEMPLATE_DIR}/Log.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/inc/${MODULE_NAME}Log.h
        @ONLY)

    configure_file(
        ${MODULES_TEMPLATE_DIR}/Log.cpp.in
        ${CMAKE_CURRENT_BINARY_DIR}/lib/${MODULE_NAME}Log.cpp
        @ONLY)

    configure_file(
        ${MODULES_TEMPLATE_DIR}/Module.cpp.in
        ${CMAKE_CURRENT_BINARY_DIR}/so/${MODULE_NAME}Module.cpp
        @ONLY)

    set(MODULE_LOGGING ${MODULE_NAME_LOWER}_logging)

    add_library(${MODULE_LOGGING} STATIC ${CMAKE_CURRENT_BINARY_DIR}/lib/${MODULE_NAME}Log.cpp)
    target_link_libraries(${MODULE_LOGGING} logging)
    target_include_directories(${MODULE_LOGGING} PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/inc)

    target_include_directories(${TARGET} PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/inc)

    set(MODULE_SO ${MODULE_NAME_LOWER})

    add_library(${MODULE_SO} SHARED ${CMAKE_CURRENT_BINARY_DIR}/so/${MODULE_NAME}Module.cpp)
    add_dependencies(${MODULE_SO} ${TARGET})

    target_link_libraries(${MODULE_SO}
        PRIVATE
            commonutils
            ${MODULE_LOGGING}
        PUBLIC
            ${TARGET})

    target_include_directories(${MODULE_SO} PUBLIC ${MODULES_INC_DIR})

    set_target_properties(${MODULE_SO}
        PROPERTIES
            PREFIX ""
            POSITION_INDEPENDENT_CODE ON)

    install(TARGETS ${MODULE_SO} DESTINATION ${MODULES_INSTALL_DIR})
endfunction()