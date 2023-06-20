cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(optee-test)
################################################################################
# Packages
################################################################################
find_package(Python REQUIRED)
set(CERT_DIR ${CMAKE_CURRENT_BINARY_DIR}/zephyr/include/generated)
macro(EMBED_8100FILE prefix infile)
	add_custom_target(
		regression_8100_${prefix}.h
		COMMAND ${Python_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/file_to_c.py --inf ${CMAKE_CURRENT_SOURCE_DIR}/${infile}
	--out ${CERT_DIR}/regression_8100_${prefix}.h
	--name regression_8100_${prefix}
		DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/file_to_c.py ${infile}
	)

	set_property(SOURCE regression_8100.c APPEND PROPERTY OBJECT_DEPENDS
		     ${CERT_DIR}/regression_8100_${prefix}.h)
	add_dependencies(app regression_8100_${prefix}.h)
endmacro(EMBED_8100FILE)

EMBED_8100FILE(ca_crt cert/ca.crt)
EMBED_8100FILE(mid_crt cert/mid.crt)
EMBED_8100FILE(my_crt cert/my.crt)
EMBED_8100FILE(my_csr cert/my.csr)

zephyr_library_sources(adbg/src/adbg_expect.c)
zephyr_library_sources(adbg/src/adbg_log.c)
zephyr_library_sources(adbg/src/security_utils_hex.c)
zephyr_include_directories(adbg/include)

zephyr_library_include_directories(include)
zephyr_library_include_directories(optee_os)
zephyr_library_sources(src/optee_test.c)
zephyr_library_sources(src/xtest_helpers.c)

zephyr_library_sources(src/regression_1000.c)
zephyr_library_sources(src/pkcs11_1000.c)
zephyr_library_sources(src/regression_4000.c)
# ######################################################################################################################
# External libs
# ######################################################################################################################

zephyr_library_include_directories(${ZEPHYR_OPTEELIB_MODULE_DIR}/public)

#add_subdirectory(adbg)

