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
#include "ngtcp2_reorder.h"

#include <assert.h>

#include "ngtcp2_macro.h"
#include "ngtcp2_unreachable.h"

void ngtcp2_reorder_init(ngtcp2_reorder *reorder,
                         ngtcp2_reorder_release release, void *user_data,
                         const ngtcp2_mem *mem) {
  *reorder = (ngtcp2_reorder){
    .release = release,
    .release_user_data = user_data,
    .mem = mem,
  };
}

static void reorder_release_entry(ngtcp2_reorder *reorder,
                                  ngtcp2_reorder_entry *ent) {
  reorder->release(&ent->buf, ent->allocator_owned, reorder->release_user_data);
  ngtcp2_mem_free(reorder->mem, ent);
}

void ngtcp2_reorder_free(ngtcp2_reorder *reorder) {
  ngtcp2_reorder_entry *ent, *next;

  if (reorder == NULL) {
    return;
  }

  for (ent = reorder->head; ent;) {
    next = ent->next;
    reorder_release_entry(reorder, ent);
    ent = next;
  }

  reorder->head = NULL;
}

static void reorder_release_buf(ngtcp2_reorder *reorder, ngtcp2_buf *buf,
                                int allocator_owned) {
  reorder->release(buf, allocator_owned, reorder->release_user_data);
}

static int reorder_entry_new(ngtcp2_reorder_entry **pent, const ngtcp2_buf *buf,
                             uint64_t begin, uint64_t end, int allocator_owned,
                             const ngtcp2_mem *mem) {
  *pent = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_reorder_entry));
  if (*pent == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  **pent = (ngtcp2_reorder_entry){
    .range =
      {
        .begin = begin,
        .end = end,
      },
    .buf = *buf,
    .allocator_owned = allocator_owned,
  };

  return 0;
}

int ngtcp2_reorder_push(ngtcp2_reorder *reorder, ngtcp2_buf *buf,
                        uint64_t offset, uint64_t cont_offset,
                        int allocator_owned, size_t *pnwrite) {
  ngtcp2_reorder_entry **pent = &reorder->head;
  ngtcp2_reorder_entry *ent;
  uint64_t begin = offset;
  uint64_t end = offset + ngtcp2_buf_len(buf);
  uint64_t n;
  int rv;

  *pnwrite = 0;

  if (end < offset) {
    return NGTCP2_ERR_FRAME_ENCODING;
  }

  if (end <= cont_offset) {
    reorder_release_buf(reorder, buf, allocator_owned);
    return 0;
  }

  if (begin < cont_offset) {
    n = cont_offset - begin;
    begin = cont_offset;
    buf->pos += n;
  }

  for (; *pent; pent = &(*pent)->next) {
    ent = *pent;

    if (ent->range.end <= begin) {
      continue;
    }
    if (end <= ent->range.begin) {
      break;
    }
    if (ent->range.begin <= begin) {
      if (end <= ent->range.end) {
        reorder_release_buf(reorder, buf, allocator_owned);
        return 0;
      }

      n = ent->range.end - begin;
      begin = ent->range.end;
      buf->pos += n;
      continue;
    }

    end = ent->range.begin;
    break;
  }

  if (begin == end) {
    reorder_release_buf(reorder, buf, allocator_owned);
    return 0;
  }

  buf->last = buf->pos + (end - begin);

  rv = reorder_entry_new(&ent, buf, begin, end, allocator_owned, reorder->mem);
  if (rv != 0) {
    return rv;
  }

  ent->next = *pent;
  *pent = ent;
  *pnwrite = (size_t)(end - begin);

  return 0;
}

uint64_t ngtcp2_reorder_first_gap_offset(const ngtcp2_reorder *reorder,
                                         uint64_t cont_offset) {
  const ngtcp2_reorder_entry *ent;
  uint64_t offset = cont_offset;

  for (ent = reorder->head; ent; ent = ent->next) {
    if (ent->range.end <= offset) {
      continue;
    }
    if (offset < ent->range.begin) {
      break;
    }

    offset = ent->range.end;
  }

  return offset;
}

size_t ngtcp2_reorder_data_at(const ngtcp2_reorder *reorder,
                              const ngtcp2_buf **pbuf, uint64_t offset) {
  const ngtcp2_reorder_entry *ent;

  for (ent = reorder->head; ent; ent = ent->next) {
    if (ent->range.end <= offset) {
      continue;
    }
    if (offset < ent->range.begin) {
      return 0;
    }

    assert(offset == ent->range.begin);

    *pbuf = &ent->buf;

    return (size_t)(ent->range.end - offset);
  }

  return 0;
}

void ngtcp2_reorder_pop(ngtcp2_reorder *reorder, uint64_t offset, size_t len) {
  ngtcp2_reorder_entry **pent = &reorder->head;
  ngtcp2_reorder_entry *ent;

  for (; *pent; pent = &(*pent)->next) {
    ent = *pent;
    if (ent->range.end <= offset) {
      continue;
    }

    assert(offset == ent->range.begin);
    assert(offset + len <= ent->range.end);

    if (offset + len < ent->range.end) {
      ent->range.begin += len;
      ent->buf.pos += len;
      return;
    }

    *pent = ent->next;
    reorder_release_entry(reorder, ent);
    return;
  }

  ngtcp2_unreachable();
}

void ngtcp2_reorder_remove_prefix(ngtcp2_reorder *reorder, uint64_t offset) {
  ngtcp2_reorder_entry *ent;

  while (reorder->head) {
    ent = reorder->head;
    if (offset <= ent->range.begin) {
      return;
    }

    if (offset < ent->range.end) {
      ent->buf.pos += offset - ent->range.begin;
      ent->range.begin = offset;
      return;
    }

    reorder->head = ent->next;
    reorder_release_entry(reorder, ent);
  }
}

int ngtcp2_reorder_data_buffered(const ngtcp2_reorder *reorder) {
  return reorder->head != NULL;
}
