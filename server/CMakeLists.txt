SET(SVC_DAEMON fido-service)

INCLUDE(FindPkgConfig)

if(USE_JSON_BUILDER)
pkg_check_modules(SERVER_pkgs REQUIRED
		dlog
		glib-2.0
		gio-unix-2.0
		gobject-2.0
		capi-base-common
		json-glib-1.0
		capi-appfw-application
		aul
		libsoup-2.4
		capi-appfw-app-manager
		capi-appfw-package-manager
		pkgmgr-info
		openssl
		bundle
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
				capi-appfw-package-manager
				pkgmgr-info
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
		fido_app_id_handler.c
		fido_privilege_checker.c
)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/common)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -Wall -Werror -fPIE")
SET(CMAKE_LDFLAGS "-Wl,-zdefs")

ADD_EXECUTABLE(${SVC_DAEMON} ${SERVER_SRCS})

TARGET_LINK_LIBRARIES(${SVC_DAEMON} ${SERVER_pkgs_LDFLAGS} fido-client-common "-pie")

INSTALL(TARGETS ${SVC_DAEMON} DESTINATION bin)

if(USE_JSON_BUILDER)
add_definitions(-DWITH_JSON_BUILDER)
else()
INSTALL(FILES ${CMAKE_SOURCE_DIR}/packaging/org.tizen.fido.service DESTINATION share/dbus-1/services)
endif()
