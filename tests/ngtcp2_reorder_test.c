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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "ngtcp2_reorder_test.h"

#include "ngtcp2_reorder.h"
#include "ngtcp2_mem.h"

typedef struct {
  int releasecnt;
  int allocator_releasecnt;
} reorder_release_data;

static const MunitTest tests[] = {
  munit_void_test(test_ngtcp2_reorder_push_data_at),
  munit_void_test(test_ngtcp2_reorder_duplicate),
  munit_void_test(test_ngtcp2_reorder_trim_prefix),
  munit_test_end(),
};

const MunitSuite reorder_suite = {
  .prefix = "/reorder",
  .tests = tests,
};

static void reorder_release(ngtcp2_buf *buf, int allocator_owned,
                            void *user_data) {
  reorder_release_data *data = user_data;

  (void)buf;

  if (allocator_owned) {
    ++data->allocator_releasecnt;
    return;
  }

  ++data->releasecnt;
}

static void init_reorder_buf(ngtcp2_buf *buf, uint8_t *data, size_t datalen) {
  ngtcp2_buf_init(buf, data, datalen, ((void *)(uintptr_t)1),
                  NGTCP2_BUF_ROLE_RX_STREAM, NULL, NULL,
                  NULL);
  buf->last = buf->end;
}

void test_ngtcp2_reorder_push_data_at(void) {
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  reorder_release_data release_data = {0};
  ngtcp2_reorder reorder;
  uint8_t data[3] = {1, 2, 3};
  ngtcp2_buf buf;
  const ngtcp2_buf *out;
  size_t nwrite, datalen;
  int rv;

  ngtcp2_reorder_init(&reorder, reorder_release, &release_data, mem);
  init_reorder_buf(&buf, data, sizeof(data));

  rv = ngtcp2_reorder_push(&reorder, &buf, 10, 0, 0, &nwrite);

  assert_int(0, ==, rv);
  assert_size(3, ==, nwrite);
  assert_uint64(0, ==, ngtcp2_reorder_first_gap_offset(&reorder, 0));
  assert_size(0, ==, ngtcp2_reorder_data_at(&reorder, &out, 0));

  ngtcp2_reorder_remove_prefix(&reorder, 10);

  assert_uint64(13, ==, ngtcp2_reorder_first_gap_offset(&reorder, 10));

  datalen = ngtcp2_reorder_data_at(&reorder, &out, 10);

  assert_size(3, ==, datalen);
  assert_ptr_equal(data, out->pos);

  ngtcp2_reorder_pop(&reorder, 10, datalen);

  assert_int(1, ==, release_data.releasecnt);
  assert_false(ngtcp2_reorder_data_buffered(&reorder));

  ngtcp2_reorder_free(&reorder);
}

void test_ngtcp2_reorder_duplicate(void) {
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  reorder_release_data release_data = {0};
  ngtcp2_reorder reorder;
  uint8_t data[10], dup[3];
  ngtcp2_buf buf, dupbuf;
  size_t nwrite;
  int rv;

  ngtcp2_reorder_init(&reorder, reorder_release, &release_data, mem);
  init_reorder_buf(&buf, data, sizeof(data));

  rv = ngtcp2_reorder_push(&reorder, &buf, 10, 0, 0, &nwrite);

  assert_int(0, ==, rv);
  assert_size(10, ==, nwrite);

  init_reorder_buf(&dupbuf, dup, sizeof(dup));

  rv = ngtcp2_reorder_push(&reorder, &dupbuf, 12, 0, 1, &nwrite);

  assert_int(0, ==, rv);
  assert_size(0, ==, nwrite);
  assert_int(0, ==, release_data.releasecnt);
  assert_int(1, ==, release_data.allocator_releasecnt);

  ngtcp2_reorder_free(&reorder);

  assert_int(1, ==, release_data.releasecnt);
}

void test_ngtcp2_reorder_trim_prefix(void) {
  const ngtcp2_mem *mem = ngtcp2_mem_default();
  reorder_release_data release_data = {0};
  ngtcp2_reorder reorder;
  uint8_t data[4] = {1, 2, 3, 4};
  ngtcp2_buf buf;
  const ngtcp2_buf *out;
  size_t nwrite, datalen;
  int rv;

  ngtcp2_reorder_init(&reorder, reorder_release, &release_data, mem);
  init_reorder_buf(&buf, data, sizeof(data));

  rv = ngtcp2_reorder_push(&reorder, &buf, 0, 2, 0, &nwrite);

  assert_int(0, ==, rv);
  assert_size(2, ==, nwrite);

  datalen = ngtcp2_reorder_data_at(&reorder, &out, 2);

  assert_size(2, ==, datalen);
  assert_ptr_equal(data + 2, out->pos);

  ngtcp2_reorder_free(&reorder);

  assert_int(1, ==, release_data.releasecnt);
}
