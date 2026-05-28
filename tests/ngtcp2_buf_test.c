/*
 * ngtcp2
 *
 * Copyright (c) 2026 ngtcp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "ngtcp2_buf_test.h"

#include "ngtcp2_buf.h"
#include "ngtcp2_conn.h"
#include "ngtcp2_err.h"
#include "ngtcp2_test_helper.h"

typedef struct buf_owner {
  size_t nretain;
  size_t nrelease;
  int fail_retain;
} buf_owner;

static int retain_owner(void *data) {
  buf_owner *owner = data;

  ++owner->nretain;

  return owner->fail_retain ? -1 : 0;
}

static void release_owner(void *data) {
  buf_owner *owner = data;

  ++owner->nrelease;
}

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_buf_validate),
  munit_void_test(test_ngtcp2_buf_retain_release),
  munit_void_test(test_ngtcp2_buf_slice),
  munit_void_test(test_ngtcp2_buf_move),
  munit_void_test(test_ngtcp2_buf_contract_error),
  munit_void_test(test_ngtcp2_conn_buf_stats),
  munit_void_test(test_ngtcp2_conn_buffer_api_contract),
  munit_test_end(),
};

const MunitSuite buf_suite = {
  .prefix = "/buf",
  .tests = tests,
};

void test_ngtcp2_buf_validate(void) {
  uint8_t raw[16];
  buf_owner owner = {0};
  ngtcp2_buf buf;

  ngtcp2_buf_init(&buf, raw, sizeof(raw), NGTCP2_BUF_ORIGIN_APPLICATION,
                  NGTCP2_BUF_DIR_RX, NGTCP2_BUF_PURPOSE_PACKET_RX, &owner,
                  retain_owner, release_owner);
  buf.last = raw + 8;

  assert_int(
    0, ==,
    ngtcp2_buf_validate(&buf, NGTCP2_BUF_DIR_RX, NGTCP2_BUF_PURPOSE_PACKET_RX));
  assert_size(8, ==, ngtcp2_buf_len(&buf));
  assert_size(sizeof(raw), ==, ngtcp2_buf_cap(&buf));
  assert_int(
    NGTCP2_ERR_BUF_CONTRACT, ==,
    ngtcp2_buf_validate(&buf, NGTCP2_BUF_DIR_TX, NGTCP2_BUF_PURPOSE_PACKET_RX));
  assert_int(
    NGTCP2_ERR_BUF_CONTRACT, ==,
    ngtcp2_buf_validate(&buf, NGTCP2_BUF_DIR_RX, NGTCP2_BUF_PURPOSE_STREAM_RX));

  buf.pos = raw + 9;
  buf.last = raw + 8;
  assert_int(
    NGTCP2_ERR_BUF_CONTRACT, ==,
    ngtcp2_buf_validate(&buf, NGTCP2_BUF_DIR_RX, NGTCP2_BUF_PURPOSE_PACKET_RX));
}

void test_ngtcp2_buf_retain_release(void) {
  uint8_t raw[1];
  buf_owner owner = {0};
  ngtcp2_buf buf;

  ngtcp2_buf_init(&buf, raw, sizeof(raw), NGTCP2_BUF_ORIGIN_APPLICATION,
                  NGTCP2_BUF_DIR_RX, NGTCP2_BUF_PURPOSE_STREAM_RX, &owner,
                  retain_owner, release_owner);
  assert_int(0, ==, ngtcp2_buf_retain_owner(&buf));
  assert_size(1, ==, owner.nretain);

  ngtcp2_buf_release_owner(&buf);
  assert_size(1, ==, owner.nrelease);
  assert_null(buf.begin);
  assert_null(buf.owner);

  ngtcp2_buf_init(&buf, raw, sizeof(raw), NGTCP2_BUF_ORIGIN_BORROWED,
                  NGTCP2_BUF_DIR_RX, NGTCP2_BUF_PURPOSE_STREAM_RX, &owner,
                  retain_owner, release_owner);
  assert_int(NGTCP2_ERR_BUF_CONTRACT, ==, ngtcp2_buf_retain_owner(&buf));

  ngtcp2_buf_init(&buf, raw, sizeof(raw), NGTCP2_BUF_ORIGIN_APPLICATION,
                  NGTCP2_BUF_DIR_RX, NGTCP2_BUF_PURPOSE_STREAM_RX, &owner, NULL,
                  release_owner);
  assert_int(NGTCP2_ERR_BUF_CONTRACT, ==, ngtcp2_buf_retain_owner(&buf));
}

void test_ngtcp2_buf_slice(void) {
  uint8_t raw[16];
  uint8_t other[1];
  buf_owner owner = {0};
  ngtcp2_buf src, dest;

  ngtcp2_buf_init(&src, raw, sizeof(raw), NGTCP2_BUF_ORIGIN_APPLICATION,
                  NGTCP2_BUF_DIR_RX, NGTCP2_BUF_PURPOSE_PACKET_RX, &owner,
                  retain_owner, release_owner);
  src.pos = raw + 2;
  src.last = raw + 10;

  dest = (ngtcp2_buf){
    .begin = other,
  };

  assert_int(0, ==,
             ngtcp2_buf_slice(&dest, &src, 3, 4, NGTCP2_BUF_PURPOSE_STREAM_RX));
  assert_size(1, ==, owner.nretain);
  assert_ptr_equal(raw, dest.begin);
  assert_ptr_equal(raw + 5, dest.pos);
  assert_ptr_equal(raw + 9, dest.last);
  assert_int(NGTCP2_BUF_PURPOSE_STREAM_RX, ==, dest.purpose);

  ngtcp2_buf_release_owner(&dest);
  assert_size(1, ==, owner.nrelease);

  owner.fail_retain = 1;
  dest = (ngtcp2_buf){
    .begin = other,
  };
  assert_int(NGTCP2_ERR_BUF_CONTRACT, ==,
             ngtcp2_buf_slice(&dest, &src, 0, 1, NGTCP2_BUF_PURPOSE_STREAM_RX));
  assert_ptr_equal(other, dest.begin);
}

void test_ngtcp2_buf_move(void) {
  uint8_t raw[4];
  buf_owner owner = {0};
  ngtcp2_buf src, dest;

  ngtcp2_buf_init(&src, raw, sizeof(raw), NGTCP2_BUF_ORIGIN_APPLICATION,
                  NGTCP2_BUF_DIR_TX, NGTCP2_BUF_PURPOSE_STREAM_TX, &owner,
                  retain_owner, release_owner);
  src.last = raw + sizeof(raw);

  ngtcp2_buf_move(&dest, &src);

  assert_null(src.begin);
  assert_ptr_equal(raw, dest.begin);
  assert_size(sizeof(raw), ==, ngtcp2_buf_len(&dest));

  ngtcp2_buf_release_owner(&src);
  assert_size(0, ==, owner.nrelease);
  ngtcp2_buf_release_owner(&dest);
  assert_size(1, ==, owner.nrelease);
}

void test_ngtcp2_buf_contract_error(void) {
  assert_string_equal("ERR_BUF_CONTRACT",
                      ngtcp2_strerror(NGTCP2_ERR_BUF_CONTRACT));
  assert_true(ngtcp2_err_is_fatal(NGTCP2_ERR_BUF_CONTRACT));
  assert_uint64(
    NGTCP2_INTERNAL_ERROR, ==,
    ngtcp2_err_infer_quic_transport_error_code(NGTCP2_ERR_BUF_CONTRACT));
}

void test_ngtcp2_conn_buf_stats(void) {
  ngtcp2_conn conn = {0};
  ngtcp2_conn_buf_stats stats;

  conn.buf_stats.rx_trailing_copy = 7;
  conn.buf_stats.app_retain = 11;

  ngtcp2_conn_get_buf_stats(&conn, &stats);
  assert_uint64(7, ==, stats.rx_trailing_copy);
  assert_uint64(11, ==, stats.app_retain);

  ngtcp2_conn_reset_buf_stats(&conn);
  ngtcp2_conn_get_buf_stats(&conn, &stats);
  assert_uint64(0, ==, stats.rx_trailing_copy);
  assert_uint64(0, ==, stats.app_retain);
}

void test_ngtcp2_conn_buffer_api_contract(void) {
  ngtcp2_conn conn = {0};
  uint8_t raw[128];
  uint8_t stream[16];
  ngtcp2_buf pkt, dest, data;

  ngtcp2_buf_init(&pkt, raw, sizeof(raw), NGTCP2_BUF_ORIGIN_BORROWED,
                  NGTCP2_BUF_DIR_RX, NGTCP2_BUF_PURPOSE_PACKET_RX, NULL, NULL,
                  NULL);
  pkt.last = pkt.end;

  assert_int(NGTCP2_ERR_BUF_CONTRACT, ==,
             ngtcp2_conn_read_pkt_versioned(&conn, NULL, 0, NULL, &pkt, 0));
  assert_uint64(1, ==, conn.buf_stats.buf_contract_failure);

  ngtcp2_buf_init(&pkt, raw, sizeof(raw), NGTCP2_BUF_ORIGIN_APPLICATION,
                  NGTCP2_BUF_DIR_RX, NGTCP2_BUF_PURPOSE_PACKET_RX, NULL, NULL,
                  NULL);
  pkt.last = pkt.end;

  assert_int(NGTCP2_ERR_BUF_CONTRACT, ==,
             ngtcp2_conn_read_pkt_versioned(&conn, NULL, 0, NULL, &pkt, 0));
  assert_uint64(2, ==, conn.buf_stats.buf_contract_failure);

  ngtcp2_buf_init(&dest, raw, sizeof(raw), NGTCP2_BUF_ORIGIN_APPLICATION,
                  NGTCP2_BUF_DIR_TX, NGTCP2_BUF_PURPOSE_PACKET_TX, NULL, NULL,
                  NULL);
  ngtcp2_buf_init(&data, stream, sizeof(stream), NGTCP2_BUF_ORIGIN_APPLICATION,
                  NGTCP2_BUF_DIR_TX, NGTCP2_BUF_PURPOSE_STREAM_TX, NULL, NULL,
                  NULL);
  data.last = data.end;

  assert_int(NGTCP2_ERR_BUF_CONTRACT, ==,
             ngtcp2_conn_write_stream_versioned(
               &conn, NULL, 0, NULL, &dest, NULL, NGTCP2_WRITE_STREAM_FLAG_NONE,
               -1, &data, 0));
  assert_uint64(3, ==, conn.buf_stats.buf_contract_failure);

  assert_int(NGTCP2_ERR_BUF_CONTRACT, ==,
             ngtcp2_conn_write_stream_versioned(
               &conn, NULL, 0, NULL, &dest, NULL, NGTCP2_WRITE_STREAM_FLAG_MORE,
               -1, &data, 0));
  assert_uint64(4, ==, conn.buf_stats.buf_contract_failure);

  assert_int(NGTCP2_ERR_BUF_CONTRACT, ==,
             ngtcp2_conn_write_stream_versioned(
               &conn, NULL, 0, NULL, &dest, NULL, NGTCP2_WRITE_STREAM_FLAG_NONE,
               0, &data, 0));
  assert_uint64(5, ==, conn.buf_stats.buf_contract_failure);
}
