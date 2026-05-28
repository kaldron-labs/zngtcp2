# ngtcp2
#
# Copyright (c) 2017 ngtcp2 contributors
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

if(ENABLE_STATIC_LIB AND LIBEV_FOUND AND HAVE_ZPICOTLS AND LIBNGHTTP3_FOUND)
  set(ptlsclient_SOURCES
    client.cc
    client_base.cc
    http3_client_proto_codec.cc
    debug.cc
    util.cc
    shared.cc
    tls_client_context_picotls.cc
    tls_client_session_picotls.cc
    tls_session_base_picotls.cc
    tls_shared_picotls.cc
    util_openssl.cc
  )

  set(ptlsserver_SOURCES
    server.cc
    server_base.cc
    http3_server_proto_codec.cc
    debug.cc
    util.cc
    http.cc
    shared.cc
    siphash.cc
    tls_server_context_picotls.cc
    tls_server_session_picotls.cc
    tls_session_base_picotls.cc
    tls_shared_picotls.cc
    util_openssl.cc
  )

  set(ptls_INCLUDE_DIRS
    ${CMAKE_SOURCE_DIR}/lib/includes
    ${CMAKE_BINARY_DIR}/lib/includes
    ${CMAKE_SOURCE_DIR}/third-party
    ${CMAKE_SOURCE_DIR}/third-party/urlparse
    ${CMAKE_SOURCE_DIR}/crypto/includes

    ${JEMALLOC_INCLUDE_DIRS}
    ${ZPICOTLS_INCLUDE_DIRS}
    ${VANILLA_OPENSSL_INCLUDE_DIRS}
    ${LIBEV_INCLUDE_DIRS}
    ${LIBNGHTTP3_INCLUDE_DIRS}
  )

  set(ptls_LIBS
    ngtcp2_crypto_zpicotls_static
    zngtcp2_static
    ${JEMALLOC_LIBRARIES}
    ${ZPICOTLS_LIBRARIES}
    ${VANILLA_OPENSSL_LIBRARIES}
    ${LIBEV_LIBRARIES}
    ${LIBNGHTTP3_LIBRARIES}
  )

  add_executable(ptlsclient ${ptlsclient_SOURCES}
    $<TARGET_OBJECTS:urlparse>
  )
  add_executable(ptlsserver ${ptlsserver_SOURCES}
    $<TARGET_OBJECTS:urlparse>
  )
  set_target_properties(ptlsclient PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DWITH_EXAMPLE_PICOTLS -DWITH_EXAMPLE_HTTP3_PROTO_CODEC"
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
  )
  set_target_properties(ptlsserver PROPERTIES
    COMPILE_FLAGS "${WARNCXXFLAGS} -DWITH_EXAMPLE_PICOTLS -DWITH_EXAMPLE_HTTP3_PROTO_CODEC"
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
  )
  target_include_directories(ptlsclient PUBLIC ${ptls_INCLUDE_DIRS})
  target_include_directories(ptlsserver PUBLIC ${ptls_INCLUDE_DIRS})
  target_link_libraries(ptlsclient ${ptls_LIBS})
  target_link_libraries(ptlsserver ${ptls_LIBS})
endif()
