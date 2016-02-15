SET(ASM_DAEMON dummyasm-service)

INCLUDE(FindPkgConfig)
pkg_check_modules(ASM_PKGS REQUIRED
                dlog
                glib-2.0
                gio-unix-2.0
                capi-base-common
                vconf
                json-glib-1.0
                capi-appfw-application
)

FOREACH(flag ${ASM_PKGS_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/common)

ADD_CUSTOM_COMMAND( OUTPUT ${CMAKE_SOURCE_DIR}/common/dummy-asm-stub.c ${CMAKE_SOURCE_DIR}/common/dummy-asm-stub.h 
WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/common/
COMMAND gdbus-codegen --interface-prefix org.tizen. --generate-c-code dummy-asm-stub ${CMAKE_SOURCE_DIR}/common/dbus_interfaces/dummyasm.xml 
COMMENT "Generating Dummy ASM GDBus stubs........................")
	
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -Wall -Werror")
SET(CMAKE_LDFLAGS "-Wl,-zdefs")

SET(DUMMY_ASM_SRCS
	dummy_asm_server.c
)

ADD_EXECUTABLE(${ASM_DAEMON} ${DUMMY_ASM_SRCS} ${CMAKE_SOURCE_DIR}/common/dummy-asm-stub.c)
ADD_DEPENDENCIES(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/common/dummy-asm-stub.h)
ADD_DEPENDENCIES(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/common/dummy-asm-stub.c)

TARGET_LINK_LIBRARIES(${ASM_DAEMON} ${ASM_PKGS_LDFLAGS})

INSTALL(TARGETS ${ASM_DAEMON} DESTINATION bin)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/test/Dummy_ASM_DBUS/dummy_asm.json DESTINATION ${LIBDIR}/fido/asm/)
