# ngtcp2

# Copyright (c) 2022 ngtcp2

# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

add_definitions(-DBUILDING_NGTCP2)

set(ngtcp2_crypto_zpicotls_SOURCES
  zpicotls.c
  ../shared.c
)

set(ngtcp2_crypto_zpicotls_INCLUDE_DIRS
  "${CMAKE_CURRENT_SOURCE_DIR}/../../lib/includes"
  "${CMAKE_CURRENT_BINARY_DIR}/../../lib/includes"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../lib"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../crypto/includes"
  "${CMAKE_CURRENT_BINARY_DIR}/../../crypto/includes"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../crypto"
  "${CMAKE_CURRENT_BINARY_DIR}/../../crypto"
  "${ZPICOTLS_INCLUDE_DIRS}"
  "${VANILLA_OPENSSL_INCLUDE_DIRS}"
)

foreach(name libzngtcp2_crypto_zpicotls.pc)
  configure_file("${name}.in" "${name}" @ONLY)
endforeach()

if(ENABLE_STATIC_LIB)
  # Public static library
  add_library(ngtcp2_crypto_zpicotls_static STATIC ${ngtcp2_crypto_zpicotls_SOURCES})
  set_target_properties(ngtcp2_crypto_zpicotls_static PROPERTIES
    COMPILE_FLAGS "${WARNCFLAGS}"
    ARCHIVE_OUTPUT_NAME zngtcp2_crypto_zpicotls${STATIC_LIB_SUFFIX}
    C_VISIBILITY_PRESET hidden
  )
  target_compile_definitions(ngtcp2_crypto_zpicotls_static PUBLIC
    "-DNGTCP2_STATICLIB")
  target_include_directories(ngtcp2_crypto_zpicotls_static PUBLIC
    ${ngtcp2_crypto_zpicotls_INCLUDE_DIRS})

  set(ngtcp2_crypto_zpicotls_TEST_LIBRARIES ${ZPICOTLS_LIBRARIES})
  if(NOT ngtcp2_crypto_zpicotls_TEST_LIBRARIES)
    set(ngtcp2_crypto_zpicotls_LIBRARY_HINTS)
    foreach(dir IN LISTS ZPICOTLS_INCLUDE_DIRS)
      list(APPEND ngtcp2_crypto_zpicotls_LIBRARY_HINTS
        "${dir}/.."
        "${dir}/../build")
    endforeach()
    find_library(NGTCP2_ZPICOTLS_OPENSSL_LIBRARY
      NAMES zpicotls-openssl picotls-openssl
      HINTS ${ngtcp2_crypto_zpicotls_LIBRARY_HINTS})
    find_library(NGTCP2_ZPICOTLS_CORE_LIBRARY
      NAMES zpicotls-core picotls-core
      HINTS ${ngtcp2_crypto_zpicotls_LIBRARY_HINTS})
    if(NGTCP2_ZPICOTLS_OPENSSL_LIBRARY AND NGTCP2_ZPICOTLS_CORE_LIBRARY)
      set(ngtcp2_crypto_zpicotls_TEST_LIBRARIES
        ${NGTCP2_ZPICOTLS_OPENSSL_LIBRARY}
        ${NGTCP2_ZPICOTLS_CORE_LIBRARY})
    endif()
  endif()

  set(ngtcp2_crypto_zpicotls_TEST_OPENSSL_LIBRARIES
    ${VANILLA_OPENSSL_LIBRARIES})
  if(NOT ngtcp2_crypto_zpicotls_TEST_OPENSSL_LIBRARIES)
    list(APPEND ngtcp2_crypto_zpicotls_TEST_OPENSSL_LIBRARIES
      ${OPENSSL_SSL_LIBRARY}
      ${OPENSSL_CRYPTO_LIBRARY})
  endif()

  if(BUILD_TESTING AND ngtcp2_crypto_zpicotls_TEST_LIBRARIES)
    add_executable(zpicotls_test EXCLUDE_FROM_ALL
      zpicotls_test.c
      ../../tests/munit/munit.c
    )
    target_compile_definitions(zpicotls_test PRIVATE BUILDING_NGTCP2)
    target_include_directories(zpicotls_test PRIVATE
      ${ngtcp2_crypto_zpicotls_INCLUDE_DIRS}
      "${CMAKE_CURRENT_SOURCE_DIR}/../../tests/munit")
    target_link_libraries(zpicotls_test
      ngtcp2_crypto_zpicotls_static
      zngtcp2_static
      ${ngtcp2_crypto_zpicotls_TEST_LIBRARIES}
      ${ngtcp2_crypto_zpicotls_TEST_OPENSSL_LIBRARIES}
      ${CMAKE_DL_LIBS})
    add_test(NAME zpicotls COMMAND zpicotls_test)
    add_dependencies(check zpicotls_test)
  elseif(BUILD_TESTING)
    message(STATUS "zpicotls provider tests disabled: zpicotls libraries not found")
  endif()

  install(TARGETS ngtcp2_crypto_zpicotls_static
    DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endif()

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libzngtcp2_crypto_zpicotls.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
