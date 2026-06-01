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
#include "ngtcp2_buf_alloc.h"

#include "ngtcp2_macro.h"
#include "ngtcp2_path.h"

#include <assert.h>
#include <string.h>

typedef struct ngtcp2_default_buf_owner {
  const ngtcp2_mem *mem;
  size_t refcount;
  uint8_t data[];
} ngtcp2_default_buf_owner;

static int buf_role_bad(ngtcp2_buf_role role) {
  return role > NGTCP2_BUF_ROLE_TX_DATAGRAM;
}

static int size_add(size_t *dest, size_t a, size_t b) {
  if (SIZE_MAX - a < b) {
    return NGTCP2_ERR_BUF_CONTRACT;
  }

  *dest = a + b;

  return 0;
}

static int validate_info(const ngtcp2_buf_alloc_info *info) {
  size_t total;

  if (info == NULL || buf_role_bad(info->role)) {
    return NGTCP2_ERR_BUF_CONTRACT;
  }

  if (info->align == 0 || (info->align & (info->align - 1))) {
    return NGTCP2_ERR_BUF_CONTRACT;
  }

  if (size_add(&total, info->headroom, info->size) != 0 ||
      size_add(&total, total, info->tailroom) != 0) {
    return NGTCP2_ERR_BUF_CONTRACT;
  }

  return 0;
}

static uint8_t *align_ptr(uint8_t *p, size_t align) {
  uintptr_t n = (uintptr_t)p;

  return (uint8_t *)((n + align - 1) & ~(uintptr_t)(align - 1));
}

static int default_owner_retain(void *owner) {
  ++((ngtcp2_default_buf_owner *)owner)->refcount;

  return 0;
}

static void default_owner_release(void *owner) {
  ngtcp2_default_buf_owner *o = owner;
  const ngtcp2_mem *mem;

  assert(o->refcount);

  if (--o->refcount) {
    return;
  }

  mem = o->mem;
  ngtcp2_mem_free(mem, o);
}

static int default_alloc(ngtcp2_buf *out, const ngtcp2_buf_alloc_info *info,
                         void *user_data) {
  const ngtcp2_mem *mem = user_data;
  ngtcp2_default_buf_owner *owner;
  uint8_t *begin;
  size_t align = info->align;
  size_t total, alloclen;
  int rv;

  rv = size_add(&total, info->headroom, info->size);
  if (rv != 0) {
    return rv;
  }
  rv = size_add(&total, total, info->tailroom);
  if (rv != 0) {
    return rv;
  }
  rv = size_add(&alloclen, sizeof(*owner), total);
  if (rv != 0) {
    return rv;
  }
  rv = size_add(&alloclen, alloclen, align - 1);
  if (rv != 0) {
    return rv;
  }

  owner = ngtcp2_mem_malloc(mem, alloclen);
  if (owner == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  owner->mem = mem;
  owner->refcount = 1;
  begin = align_ptr(owner->data, align);

  ngtcp2_buf_init(out, begin, total, info->origin, info->role, owner,
                  default_owner_retain, default_owner_release);
  out->pos = out->last = out->begin + info->headroom;

  return 0;
}

static void default_release(ngtcp2_buf *buf, void *user_data) {
  (void)user_data;
  if (buf == NULL) {
    return;
  }

  ngtcp2_buf_release_owner(buf);
}

void ngtcp2_buf_allocator_default(ngtcp2_buf_allocator *dest,
                                  const ngtcp2_mem *mem) {
  if (mem == NULL) {
    mem = ngtcp2_mem_default();
  }

  *dest = (ngtcp2_buf_allocator){
    .alloc = default_alloc,
    .release = default_release,
    .user_data = (void *)mem,
  };
}

int ngtcp2_buf_alloc(ngtcp2_buf_allocator *allocator, ngtcp2_buf *out,
                     const ngtcp2_buf_alloc_info *info) {
  int rv;

  rv = validate_info(info);
  if (rv != 0) {
    return rv;
  }
  if (allocator == NULL || allocator->alloc == NULL ||
      allocator->release == NULL) {
    return NGTCP2_ERR_BUF_CONTRACT;
  }

  rv = allocator->alloc(out, info, allocator->user_data);
  if (rv != 0) {
    return rv;
  }

  if (ngtcp2_buf_validate(out, info->role) != 0 ||
      (size_t)(out->end - out->pos) < info->size + info->tailroom) {
    allocator->release(out, allocator->user_data);
    return NGTCP2_ERR_BUF_CONTRACT;
  }

  if (info->align > 1 && ((uintptr_t)out->pos & (info->align - 1))) {
    allocator->release(out, allocator->user_data);
    return NGTCP2_ERR_BUF_CONTRACT;
  }

  return 0;
}

int ngtcp2_buf_grow(ngtcp2_buf_allocator *allocator, ngtcp2_buf *buf,
                    size_t size, const ngtcp2_buf_alloc_info *info) {
  int rv;

  rv = validate_info(info);
  if (rv != 0) {
    return rv;
  }
  if (allocator == NULL || allocator->grow == NULL) {
    return NGTCP2_ERR_BUF_CONTRACT;
  }

  return allocator->grow(buf, size, info, allocator->user_data);
}

void ngtcp2_buf_alloc_release(ngtcp2_buf_allocator *allocator, ngtcp2_buf *buf) {
  if (allocator == NULL || allocator->release == NULL) {
    return;
  }

  allocator->release(buf, allocator->user_data);
}

int ngtcp2_tx_pkt_alloc(ngtcp2_tx_pkt *out, ngtcp2_buf_allocator *allocator,
                        size_t pkt_cap, const ngtcp2_path *path,
                        const ngtcp2_pkt_info *pi) {
  ngtcp2_buf_alloc_info info;
  int rv;

  if (out == NULL || pkt_cap == 0) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  memset(out, 0, sizeof(*out));

  info = (ngtcp2_buf_alloc_info){
    .role = NGTCP2_BUF_ROLE_TX_PACKET,
    .origin = NULL,
    .size = pkt_cap,
    .align = 1,
    .flags = NGTCP2_BUF_ALLOC_FLAG_UNINITIALIZED |
             NGTCP2_BUF_ALLOC_FLAG_PACKET_DST,
  };

  rv = ngtcp2_buf_alloc(allocator, &out->pkt, &info);
  if (rv != 0) {
    return rv;
  }

  if (path) {
    ngtcp2_path_storage_init2(&out->path, path);
  } else {
    ngtcp2_path_storage_zero(&out->path);
  }

  if (pi) {
    out->pi = *pi;
  }

  out->flags = NGTCP2_TX_PKT_FLAG_RELEASE_REQUIRED;

  return 0;
}

void ngtcp2_tx_pkt_release(ngtcp2_buf_allocator *allocator, ngtcp2_tx_pkt *pkt) {
  if (allocator == NULL || allocator->release == NULL || pkt == NULL ||
      !(pkt->flags & NGTCP2_TX_PKT_FLAG_RELEASE_REQUIRED)) {
    return;
  }

  ngtcp2_buf_alloc_release(allocator, &pkt->pkt);
  ngtcp2_path_storage_zero(&pkt->path);
  pkt->pi = (ngtcp2_pkt_info){0};
  pkt->gso_size = 0;
  pkt->flags = NGTCP2_TX_PKT_FLAG_NONE;
}
