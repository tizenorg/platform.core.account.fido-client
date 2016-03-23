
SET(CLIENT_SRCS
	fido_uaf_client.c
	fido_uaf_authenticator.c
	../common/fido_json_handler.c
        ../common/fido_b64_util.c
    ../common/fido_tlv_util.c
    ../common/fido_uaf_utils.c
)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/common)

INCLUDE(FindPkgConfig)
pkg_check_modules(CLIENT_PKGS REQUIRED
		dlog
		glib-2.0
		gio-unix-2.0
		capi-base-common
		json-glib-1.0
		openssl
		gobject-2.0
)

FOREACH(flag ${CLIENT_PKGS_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -Wall -Werror")
SET(CMAKE_LDFLAGS "-Wl,-zdefs")

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DFACTORYFS=\"$ENV{FACTORYFS}\"")
ADD_DEFINITIONS("-DSLP_DEBUG")

ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_SOURCE_DIR}/common/fido-stub.c ${CMAKE_SOURCE_DIR}/common/fido-stub.h
WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/common/
COMMAND gdbus-codegen --interface-prefix org.tizen. --generate-c-code fido-stub ${CMAKE_SOURCE_DIR}/common/dbus_interfaces/fido.xml 
COMMENT "Generating FIDO GDBus stubs........................")

ADD_LIBRARY(${PROJECT_NAME} SHARED ${CLIENT_SRCS} ${CMAKE_SOURCE_DIR}/common/fido-stub.c)
ADD_DEPENDENCIES(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/common/fido-stub.h)
ADD_DEPENDENCIES(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/common/fido-stub.c)

SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES VERSION ${VERSION})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${CLIENT_PKGS_LDFLAGS})

INSTALL(TARGETS ${PROJECT_NAME} DESTINATION ${LIBDIR})

INSTALL(FILES ${CMAKE_SOURCE_DIR}/include/fido.h DESTINATION include)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/include/fido_uaf_authenticator.h DESTINATION include)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/include/fido_uaf_client.h DESTINATION include)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/common/fido_uaf_types.h DESTINATION include)

CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/client/${PROJECT_NAME}.pc.in ${CMAKE_SOURCE_DIR}/client/${PROJECT_NAME}.pc @ONLY)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/client/${PROJECT_NAME}.pc DESTINATION ${LIBDIR}/pkgconfig)
