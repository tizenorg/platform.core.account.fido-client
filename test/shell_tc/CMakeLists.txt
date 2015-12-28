SET(FIDO_SHELL_TC fido-shell-tc)

INCLUDE(FindPkgConfig)
pkg_check_modules(FIDO_SHELL_TC_PKGS REQUIRED
                dlog
                glib-2.0
                gio-unix-2.0
                capi-base-common
)

FOREACH(flag ${FIDO_SHELL_TC_PKGS_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/test/shell_tc)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/common)


SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -Wall -Werror -Wno-unused-result")
SET(CMAKE_LDFLAGS "-Wl,-zdefs")

SET(FIDO_SHELL_TC_SRCS
	fido_shell_tc_util.c
	fido_shell_tc.c
)

ADD_EXECUTABLE(${FIDO_SHELL_TC} ${FIDO_SHELL_TC_SRCS})

TARGET_LINK_LIBRARIES(${FIDO_SHELL_TC} ${FIDO_SHELL_TC_LDFLAGS})
TARGET_LINK_LIBRARIES(${FIDO_SHELL_TC} fido-client)

INSTALL(TARGETS ${FIDO_SHELL_TC} DESTINATION /opt/usr/devel/fido/tc)
