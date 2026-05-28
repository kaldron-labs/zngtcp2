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
#ifndef NGTCP2_REORDER_H
#define NGTCP2_REORDER_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <zngtcp2/zngtcp2.h>

#include "ngtcp2_mem.h"
#include "ngtcp2_range.h"

typedef void (*ngtcp2_reorder_release)(ngtcp2_buf *buf, int allocator_owned,
                                       void *user_data);

typedef struct ngtcp2_reorder_entry {
  ngtcp2_range range;
  ngtcp2_buf buf;
  int allocator_owned;
  struct ngtcp2_reorder_entry *next;
} ngtcp2_reorder_entry;

typedef struct ngtcp2_reorder {
  ngtcp2_reorder_entry *head;
  ngtcp2_reorder_release release;
  void *release_user_data;
  const ngtcp2_mem *mem;
} ngtcp2_reorder;

void ngtcp2_reorder_init(ngtcp2_reorder *reorder,
                         ngtcp2_reorder_release release, void *user_data,
                         const ngtcp2_mem *mem);
void ngtcp2_reorder_free(ngtcp2_reorder *reorder);

int ngtcp2_reorder_push(ngtcp2_reorder *reorder, ngtcp2_buf *buf,
                        uint64_t offset, uint64_t cont_offset,
                        int allocator_owned, size_t *pnwrite);
size_t ngtcp2_reorder_data_at(const ngtcp2_reorder *reorder,
                              const ngtcp2_buf **pbuf, uint64_t offset);
void ngtcp2_reorder_pop(ngtcp2_reorder *reorder, uint64_t offset, size_t len);
void ngtcp2_reorder_remove_prefix(ngtcp2_reorder *reorder, uint64_t offset);
uint64_t ngtcp2_reorder_first_gap_offset(const ngtcp2_reorder *reorder,
                                         uint64_t cont_offset);
int ngtcp2_reorder_data_buffered(const ngtcp2_reorder *reorder);

#endif /* !defined(NGTCP2_REORDER_H) */
