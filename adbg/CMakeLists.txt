# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023 EPAM Systems
# Author: Dmytro Semenets <dmytro_semenets@epam.com>

add_library(OPTEE_TEST_ADBG INTERFACE)

target_include_directories(OPTEE_TEST_ADBG INTERFACE include)

zephyr_library()
#zephyr_library_sources(src/adbg_case.c)
#zephyr_library_sources(src/adbg_enum.c)
zephyr_library_sources(src/adbg_expect.c)
zephyr_library_sources(src/adbg_log.c)
#zephyr_library_sources(src/adbg_run.c)
zephyr_library_sources(src/security_utils_hex.c)

zephyr_library_link_libraries(OPTEE_TEST_ADBG)
zephyr_include_directories(include)
