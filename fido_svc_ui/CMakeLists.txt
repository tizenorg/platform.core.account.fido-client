
SET (UI_PACKAGE_NAME "org.tizen.fidosvcui")

SET(UI_SRCS 
        ${CMAKE_SOURCE_DIR}/fido_svc_ui/fido_ui_server.c
)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/common)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

ADD_DEFINITIONS("-DPACKAGE=\"${PACKAGE_NAME}\"")

INCLUDE(FindPkgConfig)
pkg_check_modules(UI_PKGS REQUIRED
		elementary
		efl-extension
		capi-appfw-application
		capi-system-system-settings
		dlog
		json-glib-1.0
		glib-2.0
		gio-unix-2.0)

FOREACH(flag ${UI_PKGS_CFLAGS})
	SET(EXTRA_CFLGAS "${EXTRA_CFLGAS} ${flag}")
ENDFOREACH(flag)

ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_SOURCE_DIR}/common/fido-stub.c ${CMAKE_SOURCE_DIR}/common/fido-stub.h
WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/common/
COMMAND gdbus-codegen --interface-prefix org.tizen. --generate-c-code fido-stub ${CMAKE_SOURCE_DIR}/common/dbus_interfaces/fido.xml
COMMENT "Generating FIDO GDBus stubs........................")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE ${EXTRA_CFLGAS}")
ADD_EXECUTABLE(${UI_PACKAGE_NAME} ${UI_SRCS} ${CMAKE_SOURCE_DIR}/common/fido-stub.c)
ADD_DEPENDENCIES(${UI_PACKAGE_NAME} ${CMAKE_SOURCE_DIR}/common/fido-stub.h)
ADD_DEPENDENCIES(${UI_PACKAGE_NAME} ${CMAKE_SOURCE_DIR}/common/fido-stub.c)
TARGET_LINK_LIBRARIES(${UI_PACKAGE_NAME} "-pie" ${UI_PKGS_LDFLAGS})
CONFIGURE_FILE(${UI_PACKAGE_NAME}.xml.in ${UI_PACKAGE_NAME}.xml)

INSTALL(TARGETS ${UI_PACKAGE_NAME} DESTINATION ${BIN_DIR})
INSTALL(FILES ${UI_PACKAGE_NAME}.xml DESTINATION ${MANIFEST_DIR})
INSTALL(FILES ${CMAKE_SOURCE_DIR}/fido_svc_ui/${UI_PACKAGE_NAME}.png DESTINATION ${ICON_DIR})
