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
#ifndef NGTCP2_BUF_ALLOC_H
#define NGTCP2_BUF_ALLOC_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include "ngtcp2_buf.h"
#include "ngtcp2_mem.h"

/*
 * ngtcp2_buf_alloc calls |allocator| with deterministic role/allocation
 * validation.
 */
int ngtcp2_buf_alloc(ngtcp2_buf_allocator *allocator, ngtcp2_buf *out,
                     const ngtcp2_buf_alloc_info *info);

/*
 * ngtcp2_buf_grow grows |buf| through |allocator|.
 */
int ngtcp2_buf_grow(ngtcp2_buf_allocator *allocator, ngtcp2_buf *buf,
                    size_t size, const ngtcp2_buf_alloc_info *info);

/*
 * ngtcp2_buf_alloc_release releases |buf| through |allocator|.
 */
void ngtcp2_buf_alloc_release(ngtcp2_buf_allocator *allocator, ngtcp2_buf *buf);

/*
 * ngtcp2_tx_pkt_alloc allocates a TX packet handoff buffer.
 */
int ngtcp2_tx_pkt_alloc(ngtcp2_tx_pkt *out, ngtcp2_buf_allocator *allocator,
                        size_t pkt_cap, const ngtcp2_path *path,
                        const ngtcp2_pkt_info *pi);

#endif /* !defined(NGTCP2_BUF_ALLOC_H) */
