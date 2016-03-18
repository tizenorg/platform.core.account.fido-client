SET(SVC_DAEMON fido-service)

INCLUDE(FindPkgConfig)

if(USE_JSON_BUILDER)
pkg_check_modules(SERVER_pkgs REQUIRED
                dlog
                glib-2.0
                gio-unix-2.0
                capi-base-common
                json-glib-1.0
                capi-appfw-application
                aul
                libsoup-2.4
                capi-appfw-app-manager
                openssl
                bundle
                cynara-client
                cynara-session
                cynara-creds-gdbus
                libtzplatform-config
)
else()
pkg_check_modules(SERVER_pkgs REQUIRED
                dlog
                glib-2.0
                gio-unix-2.0
                capi-base-common
                json-glib-1.0
                capi-appfw-application
                aul
                libsoup-2.4
                capi-appfw-app-manager
                openssl
                bundle
)
endif()

FOREACH(flag ${SERVER_pkgs_CFLAGS})
    SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(SERVER_SRCS
        fido_server.c
        fido_asm_plugin_manager.c
        fido_uaf_policy_checker.c
        fido_selection_ui_adaptor.c
        ../common/fido_uaf_utils.c
        ../common/fido_json_handler.c
        ../common/fido_tlv_util.c
        fido_app_id_handler.c
        ../common/fido_b64_util.c
        fido_privilege_checker.c
)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/common)

ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_SOURCE_DIR}/common/fido-stub.c ${CMAKE_SOURCE_DIR}/common/fido-stub.h
WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/common/
COMMAND gdbus-codegen --interface-prefix org.tizen. --generate-c-code fido-stub ${CMAKE_SOURCE_DIR}/common/dbus_interfaces/fido.xml 
COMMENT "Generating FIDO GDBus stubs........................")
	
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -Wall -Werror")
SET(CMAKE_LDFLAGS "-Wl,-zdefs")

ADD_EXECUTABLE(${SVC_DAEMON} ${SERVER_SRCS} ${CMAKE_SOURCE_DIR}/common/fido-stub.c)
ADD_DEPENDENCIES(${SVC_DAEMON} ${CMAKE_SOURCE_DIR}/common/fido-stub.h)
ADD_DEPENDENCIES(${SVC_DAEMON} ${CMAKE_SOURCE_DIR}/common/fido-stub.c)

TARGET_LINK_LIBRARIES(${SVC_DAEMON} ${SERVER_pkgs_LDFLAGS})

INSTALL(TARGETS ${SVC_DAEMON} DESTINATION bin)

if(USE_JSON_BUILDER)
add_definitions(-DWITH_JSON_BUILDER)
else()
INSTALL(FILES ${CMAKE_SOURCE_DIR}/packaging/org.tizen.fido.service DESTINATION share/dbus-1/services)
endif()

