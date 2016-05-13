
SET(FIDO_COMMON fido-client-common)

SET(FIDO_COMMON_SRCS
	fido_json_handler.c
	fido_b64_util.c
	fido_tlv_util.c
	fido_uaf_utils.c
)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/common)

INCLUDE(FindPkgConfig)
pkg_check_modules(FIDO_COMMON_PKGS REQUIRED
		dlog
		glib-2.0
		gio-unix-2.0
		gobject-2.0
		capi-base-common
		json-glib-1.0
		openssl
)

FOREACH(flag ${FIDO_COMMON_PKGS_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -Wall -Werror")
SET(CMAKE_LDFLAGS "-Wl,-zdefs")

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DFACTORYFS=\"$ENV{FACTORYFS}\"")
ADD_DEFINITIONS("-DSLP_DEBUG")

if(USE_JSON_BUILDER)
add_definitions(-DWITH_JSON_BUILDER)
endif()

ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_SOURCE_DIR}/common/fido-stub.c ${CMAKE_SOURCE_DIR}/common/fido-stub.h
WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/common/
COMMAND gdbus-codegen --interface-prefix org.tizen. --generate-c-code fido-stub ${CMAKE_SOURCE_DIR}/common/dbus_interfaces/fido.xml
COMMENT "Generating FIDO GDBus stubs........................")

ADD_LIBRARY(${FIDO_COMMON} STATIC ${FIDO_COMMON_SRCS} ${CMAKE_SOURCE_DIR}/common/fido-stub.c)
ADD_DEPENDENCIES(${FIDO_COMMON} ${CMAKE_SOURCE_DIR}/common/fido-stub.h)
ADD_DEPENDENCIES(${FIDO_COMMON} ${CMAKE_SOURCE_DIR}/common/fido-stub.c)


TARGET_LINK_LIBRARIES(${FIDO_COMMON} ${FIDO_COMMON_PKGS_LDFLAGS})

INSTALL(TARGETS ${CLIENT_LIB} DESTINATION ${LIBDIR})
