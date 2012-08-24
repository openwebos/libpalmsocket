# @@@LICENSE
#
# Copyright (c) 2009-2012 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# LICENSE@@@

cmake_minimum_required(VERSION 2.8.7)

project(palmsocket C)

include(webOS/webOS)
webos_modules_init(1 0 0 QUALIFIER RC2)
webos_component(2 0 0)

include(FindPkgConfig)
pkg_check_modules(GLIB2 REQUIRED glib-2.0)
include_directories(${GLIB2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${GLIB2_CFLAGS_OTHER})

pkg_check_modules(OPENSSL REQUIRED openssl)
include_directories(${OPENSSL_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${OPENSSL_CFLAGS_OTHER})

pkg_check_modules(PMLOG REQUIRED PmLogLib)
include_directories(${PMLOG_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PMLOG_CFLAGS_OTHER})

pkg_check_modules(CARES REQUIRED libcares)
include_directories(${CARES_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${CARES_CFLAGS_OTHER})

pkg_check_modules(PMSTATEMACHINE REQUIRED PmStateMachineEngine)
include_directories(${PMSTATEMACHINE_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PMSTATEMACHINE_CFLAGS_OTHER})

# Adding -Wno-deprecated-declarations flag to stop warnings for 
# some glib functions on older Ubuntu versions
webos_add_compiler_flags(ALL -Wno-deprecated-declarations)

include_directories(include/public/palmsocket)

file(GLOB SOURCE_FILES src/*.c)

add_library(palmsocket SHARED ${SOURCE_FILES})
target_link_libraries(palmsocket ${GLIB2_LDFLAGS} ${OPENSSL_LDFLAGS} ${PMLOG_LDFLAGS} ${CARES_LDFLAGS} ${PMSTATEMACHINE_LDFLAGS})
webos_build_pkgconfig()
webos_build_library() 
