# ngtcp2
#
# Copyright (c) 2016 ngtcp2 contributors
# Copyright (c) 2012 nghttp2 contributors
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

cmake_minimum_required(VERSION 3.20)

# Allow setting VISIBILITY_PRESET on static library targets without warning.
cmake_policy(SET CMP0063 NEW)

# XXX using 0.1.90 instead of 0.2.0-DEV
project(zngtcp2 VERSION 1.22.90 LANGUAGES C)

# See versioning rule:
#  https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
set(LT_CURRENT  24)
set(LT_REVISION 1)
set(LT_AGE      8)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" "${CMAKE_MODULE_PATH}")
include(Version)

math(EXPR LT_SOVERSION "${LT_CURRENT} - ${LT_AGE}")
set(LT_VERSION "${LT_SOVERSION}.${LT_AGE}.${LT_REVISION}")

set(PACKAGE_VERSION     "${PROJECT_VERSION}")
HexVersion(PACKAGE_VERSION_NUM ${PROJECT_VERSION_MAJOR} ${PROJECT_VERSION_MINOR} ${PROJECT_VERSION_PATCH})

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Choose the build type" FORCE)

  # Include "None" as option to disable any additional (optimization) flags,
  # relying on just CMAKE_C_FLAGS and CMAKE_CXX_FLAGS (which are empty by
  # default). These strings are presented in cmake-gui.
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    "None" "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

include(GNUInstallDirs)
include(CMakeDependentOption)

include(CMakeOptions.txt)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Do not disable assertions based on CMAKE_BUILD_TYPE.
foreach(_build_type "Release" "MinSizeRel" "RelWithDebInfo")
  foreach(_lang C CXX)
    string(TOUPPER "CMAKE_${_lang}_FLAGS_${_build_type}" _var)
    string(REGEX REPLACE "(^| )[/-]D *NDEBUG($| )" " " ${_var} "${${_var}}")
  endforeach()
endforeach()

if(NOT ENABLE_LIB_ONLY)
  enable_language(CXX)
endif()

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

include(CMakePushCheckState)

if(NOT CMAKE_C_COMPILER_ID MATCHES "MSVC")
  if(ENABLE_ASAN)
    cmake_push_check_state()
    set(CMAKE_REQUIRED_LIBRARIES "-fsanitize=address")
    check_c_compiler_flag(-fsanitize=address C__fsanitize_address_VALID)
    if(ENABLE_LIB_ONLY)
      # Bypass C++-specific check for lib-only builds where C++ is not enabled.
      set(CXX__fsanitize_address_VALID TRUE)
    else()
      check_cxx_compiler_flag(-fsanitize=address CXX__fsanitize_address_VALID)
    endif()
    cmake_pop_check_state()
    if(NOT C__fsanitize_address_VALID OR NOT CXX__fsanitize_address_VALID)
      message(WARNING "ENABLE_ASAN was requested, but not supported!")
    else()
      set(CMAKE_C_FLAGS "-fsanitize=address ${CMAKE_C_FLAGS}")
      set(CMAKE_CXX_FLAGS "-fsanitize=address ${CMAKE_CXX_FLAGS}")
    endif()
  endif()
endif()

find_package(OpenSSL 1.1.1 REQUIRED)
find_package(PkgConfig QUIET)
if(ENABLE_JEMALLOC)
  find_package(Jemalloc REQUIRED)
endif()
if(NOT ENABLE_LIB_ONLY)
  find_package(Libev 4.11)
  find_package(Libnghttp3 1.14.0)
  find_package(Libbrotlienc 1.0.9)
  find_package(Libbrotlidec 1.0.9)
endif()

enable_testing()
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})

# OpenSSL is required by zpicotls' OpenSSL-backed crypto primitives.
include(CheckSymbolExists)
set(VANILLA_OPENSSL_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
set(VANILLA_OPENSSL_LIBRARIES ${OPENSSL_LIBRARIES})
set(HAVE_OPENSSL TRUE)

# zpicotls is the only supported crypto provider for zngtcp2.
include(CheckIncludeFile)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_ZPICOTLS QUIET IMPORTED_TARGET zpicotls-openssl)
endif()
if(PC_ZPICOTLS_FOUND)
  set(ZPICOTLS_PKGCONFIG_LIBRARIES PkgConfig::PC_ZPICOTLS)
endif()
if(NOT ZPICOTLS_INCLUDE_DIR AND PC_ZPICOTLS_FOUND)
  set(ZPICOTLS_INCLUDE_DIRS ${PC_ZPICOTLS_INCLUDE_DIRS})
else()
  set(ZPICOTLS_INCLUDE_DIRS ${ZPICOTLS_INCLUDE_DIR})
endif()
if(NOT ZPICOTLS_INCLUDE_DIR AND NOT PC_ZPICOTLS_FOUND
   AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../zpicotls/include")
  set(ZPICOTLS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../zpicotls/include")
  set(ZPICOTLS_INCLUDE_DIRS ${ZPICOTLS_INCLUDE_DIR})
endif()
if(NOT ZPICOTLS_LIBRARIES AND PC_ZPICOTLS_FOUND)
  set(ZPICOTLS_LIBRARIES ${ZPICOTLS_PKGCONFIG_LIBRARIES})
endif()
cmake_push_check_state()
set(CMAKE_REQUIRED_INCLUDES
  "${ZPICOTLS_INCLUDE_DIRS}"
  "${VANILLA_OPENSSL_INCLUDE_DIRS}")
set(CMAKE_REQUIRED_LIBRARIES
  "${ZPICOTLS_LIBRARIES}"
  "${VANILLA_OPENSSL_LIBRARIES}")
check_include_file("zpicotls.h" HAVE_ZPICOTLS_H)
check_include_file("zpicotls/openssl.h" HAVE_ZPICOTLS_OPENSSL_H)
cmake_pop_check_state()
if(NOT HAVE_ZPICOTLS_H OR NOT HAVE_ZPICOTLS_OPENSSL_H)
  message(FATAL_ERROR
    "zpicotls with QUIC buffer hooks was not found; install zpicotls-openssl.pc or set ZPICOTLS_INCLUDE_DIR and ZPICOTLS_LIBRARIES")
endif()
set(HAVE_ZPICOTLS TRUE)
set(HAVE_CRYPTO TRUE)

# jemalloc
set(HAVE_JEMALLOC ${JEMALLOC_FOUND})
# libev (required for examples)
set(HAVE_LIBEV      ${LIBEV_FOUND})
# libnghttp3 (required for examples)
set(HAVE_LIBNGHTTP3 ${LIBNGHTTP3_FOUND})

# libbrotli (required for certificate compression)
set(HAVE_LIBBROTLIENC ${LIBBROTLIENC_FOUND})
set(HAVE_LIBBROTLIDEC ${LIBBROTLIDEC_FOUND})
if(LIBBROTLIENC_FOUND AND LIBBROTLIDEC_FOUND)
  set(HAVE_LIBBROTLI 1)
endif()

# Checks for header files.
include(CheckIncludeFile)
check_include_file("arpa/inet.h"   HAVE_ARPA_INET_H)
check_include_file("netinet/in.h"  HAVE_NETINET_IN_H)
check_include_file("netinet/ip.h"  HAVE_NETINET_IP_H)
check_include_file("unistd.h"      HAVE_UNISTD_H)
check_include_file("sys/endian.h"  HAVE_SYS_ENDIAN_H)
check_include_file("endian.h"      HAVE_ENDIAN_H)
check_include_file("byteswap.h"    HAVE_BYTESWAP_H)
check_include_file("asm/types.h"   HAVE_ASM_TYPES_H)
check_include_file("linux/netlink.h"   HAVE_LINUX_NETLINK_H)
check_include_file("linux/rtnetlink.h" HAVE_LINUX_RTNETLINK_H)

include(CheckTypeSize)
# Checks for typedefs, structures, and compiler characteristics.
# AC_TYPE_SIZE_T
check_type_size("ssize_t" SIZEOF_SSIZE_T)
if(SIZEOF_SSIZE_T STREQUAL "")
  # ssize_t is a signed type in POSIX storing at least -1.
  # Set it to a pointer-size int.
  set(ssize_t ptrdiff_t)
endif()

# Checks for symbols.
if(HAVE_ENDIAN_H)
  check_symbol_exists(be64toh "endian.h" HAVE_DECL_BE64TOH)
endif()
if(NOT HAVE_DECL_BE64TOH AND HAVE_SYS_ENDIAN_H)
  check_symbol_exists(be64toh "sys/endian.h" HAVE_DECL_BE64TOH)
endif()

check_symbol_exists(bswap_64 "byteswap.h" HAVE_DECL_BSWAP_64)
check_symbol_exists(explicit_bzero "string.h" HAVE_EXPLICIT_BZERO)
check_symbol_exists(memset_s "string.h" HAVE_MEMSET_S)

if(${CMAKE_C_BYTE_ORDER} STREQUAL "BIG_ENDIAN")
  set(WORDS_BIGENDIAN 1)
endif()

set(WARNCFLAGS)
set(WARNCXXFLAGS)
if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
  if(ENABLE_WERROR)
    set(WARNCFLAGS    /WX)
    set(WARNCXXFLAGS  /WX)
  endif()
else()
  if(ENABLE_WERROR)
    set(WARNCFLAGS   "-Werror")
    set(WARNCXXFLAGS "-Werror")
  endif()

  include(PickyWarningsC)
  include(PickyWarningsCXX)
endif()

if(ENABLE_DEBUG)
  set(DEBUGBUILD 1)
endif()

add_definitions(-DHAVE_CONFIG_H)
configure_file(cmakeconfig.h.in config.h)
# autotools-compatible names
# Sphinx expects relative paths in the .rst files. Use the fact that the files
# below are all one directory level deep.
file(RELATIVE_PATH top_srcdir   "${CMAKE_CURRENT_BINARY_DIR}/dir" "${CMAKE_CURRENT_SOURCE_DIR}")
file(RELATIVE_PATH top_builddir "${CMAKE_CURRENT_BINARY_DIR}/dir" "${CMAKE_CURRENT_BINARY_DIR}")
set(abs_top_srcdir  "${CMAKE_CURRENT_SOURCE_DIR}")
set(abs_top_builddir "${CMAKE_CURRENT_BINARY_DIR}")
# libzngtcp2.pc (pkg-config file)
set(prefix          "${CMAKE_INSTALL_PREFIX}")
set(exec_prefix     "${CMAKE_INSTALL_PREFIX}")
set(libdir          "${CMAKE_INSTALL_FULL_LIBDIR}")
set(includedir      "${CMAKE_INSTALL_FULL_INCLUDEDIR}")
set(VERSION         "${PACKAGE_VERSION}")
# For init scripts and systemd service file (in contrib/)
set(bindir          "${CMAKE_INSTALL_FULL_BINDIR}")
set(sbindir         "${CMAKE_INSTALL_FULL_SBINDIR}")
foreach(name
  lib/libzngtcp2.pc
  lib/includes/zngtcp2/version.h
)
  configure_file("${name}.in" "${name}" @ONLY)
endforeach()

if(APPLE)
  add_definitions(-D__APPLE_USE_RFC_3542)
endif()

if(ENABLE_SHARED_LIB AND ENABLE_STATIC_LIB AND MSVC AND NOT STATIC_LIB_SUFFIX)
  set(STATIC_LIB_SUFFIX "_static")
endif()

include_directories(
  "${CMAKE_CURRENT_BINARY_DIR}" # for config.h
)
# For use in src/CMakeLists.txt
set(PKGDATADIR "${CMAKE_INSTALL_FULL_DATADIR}/${CMAKE_PROJECT_NAME}")

install(FILES README.rst DESTINATION "${CMAKE_INSTALL_DOCDIR}")

add_subdirectory(lib)
if(BUILD_TESTING)
  add_subdirectory(tests)
endif()
add_subdirectory(crypto)
add_subdirectory(third-party)
if(NOT ENABLE_LIB_ONLY)
  add_subdirectory(examples)
endif()

string(TOUPPER "${CMAKE_BUILD_TYPE}" _build_type)
message(STATUS "summary of build options:

    Package version: ${VERSION}
    Library version: ${LT_CURRENT}:${LT_REVISION}:${LT_AGE}
    Install prefix:  ${CMAKE_INSTALL_PREFIX}
    Target system:   ${CMAKE_SYSTEM_NAME}
    Compiler:
      Build type:     ${CMAKE_BUILD_TYPE}
      C compiler:     ${CMAKE_C_COMPILER}
      CFLAGS:         ${CMAKE_C_FLAGS_${_build_type}} ${CMAKE_C_FLAGS}
      C++ compiler:   ${CMAKE_CXX_COMPILER}
      CXXFLAGS:       ${CMAKE_CXX_FLAGS_${_build_type}} ${CMAKE_CXX_FLAGS}
      WARNCFLAGS:     ${WARNCFLAGS}
      WARNCXXFLAGS:   ${WARNCXXFLAGS}
    Library:
      Shared:         ${ENABLE_SHARED_LIB}
      Static:         ${ENABLE_STATIC_LIB}
    Test:
      Build Test:     ${BUILD_TESTING}
    Libs:
      OpenSSL:        ${HAVE_OPENSSL} (LIBS='${OPENSSL_LIBRARIES}')
      Libev:          ${HAVE_LIBEV} (LIBS='${LIBEV_LIBRARIES}')
      Libnghttp3:     ${HAVE_LIBNGHTTP3} (LIBS='${LIBNGHTTP3_LIBRARIES}')
      zpicotls:       ${HAVE_ZPICOTLS} (LIBS='${ZPICOTLS_LIBRARIES}')
      Jemalloc:       ${HAVE_JEMALLOC} (LIBS='${JEMALLOC_LIBRARIES}')
      Libbrotlienc:   ${HAVE_LIBBROTLIENC} (LIBS='${LIBBROTLIENC_LIBRARIES}')
      Libbrotlidec:   ${HAVE_LIBBROTLIDEC} (LIBS='${LIBBROTLIDEC_LIBRARIES}')
")
