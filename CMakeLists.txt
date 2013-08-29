CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(secure-storage C)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(INCLUDEDIR "\${prefix}/include")
SET(VERSION_MAJOR 1)
SET(VERSION ${VERSION_MAJOR}.0.0)

#Verbose
#SET(CMAKE_VERBOSE_MAKEFILE ON)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED dukgenerator libsystemd-daemon)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(ss_dir "./")
SET(ss_include_dir "./include")
SET(ss_client_dir "./client/src")
SET(ss_client_include_dir "./client/include")
SET(ss_server_dir "./server/src")
SET(ss_server_include_dir "./server/include")
SET(ss_test_dir "./testcases")

## About debug
#SET(debug_type "") 					# for debug - use no debugging
#SET(debug_type "-DSS_CONSOLE_USE") 		# for debug - use console window
SET(debug_type "-DSS_DLOG_USE") 		# for debug - use dlog 
#SET(debug_type "") 						# for debug - DO NOT use
SET(use_key "-DUSE_KEY_FILE")		# for private key - use key file
#SET(use_key "-DUSE_NOT")			# for private key - use no private key, key will be fixed
SET(smack_groupid "-DSMACK_GROUP_ID") # for group id sharing with smack label

SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

###################################################################################################
## for libss-client.so (library)
SET(libss-client_SOURCES ${ss_client_dir}/ss_client_intf.c ${ss_client_dir}/ss_client_ipc.c ${ss_client_dir}/ss_manager.c)
SET(libss-client_LDFLAGS " -module -avoid-version ${OPENSSL_LIBS}")
SET(libss-client_CFLAGS  " ${CFLAGS} -fPIC -I${ss_client_include_dir} -I${ss_include_dir} ${OPENSSL_CFLAGS} ${debug_type} ")
#SET(libss-client_LIBADD " ${OPENSSL_LIBS} ")

ADD_LIBRARY(ss-client SHARED ${libss-client_SOURCES})
TARGET_LINK_LIBRARIES(ss-client ${pkgs_LDFLAGS})
SET_TARGET_PROPERTIES(ss-client PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(ss-client PROPERTIES VERSION ${VERSION})
SET_TARGET_PROPERTIES(ss-client PROPERTIES COMPILE_FLAGS "${libss-client_CFLAGS}")
###################################################################################################

###################################################################################################
## for ss-server (binary)
SET(ss-server_SOURCES ${ss_server_dir}/ss_server_ipc.c ${ss_server_dir}/ss_server_main.c)
SET(ss-server_CFLAGS " -I. -I${ss_include_dir} -I${ss_server_include_dir} ${debug_type} ${use_key} ${OPENSSL_CFLAGS} ${smack_groupid} -D_GNU_SOURCE ")
SET(ss-server_LDFLAGS ${pkgs_LDFLAGS})

ADD_EXECUTABLE(ss-server ${ss-server_SOURCES})
TARGET_LINK_LIBRARIES(ss-server ${pkgs_LDFLAGS} -lsecurity-server-client )
SET_TARGET_PROPERTIES(ss-server PROPERTIES COMPILE_FLAGS "${ss-server_CFLAGS}")
####################################################################################################

CONFIGURE_FILE(secure-storage.pc.in secure-storage.pc @ONLY)
CONFIGURE_FILE(config.in config @ONLY)

INSTALL(TARGETS ss-client DESTINATION ${LIB_INSTALL_DIR})
INSTALL(PROGRAMS ${CMAKE_BINARY_DIR}/ss-server DESTINATION bin)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/secure-storage.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/config DESTINATION share/secure-storage/)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/ss_manager.h DESTINATION include)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/systemd/secure-storage.service DESTINATION /usr/lib/systemd/system)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/systemd/secure-storage.socket DESTINATION /usr/lib/systemd/system)
