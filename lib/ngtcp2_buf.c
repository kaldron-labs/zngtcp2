/*
 * ngtcp2
 *
 * Copyright (c) 2017 ngtcp2 contributors
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
#include "ngtcp2_buf.h"
#include "ngtcp2_mem.h"

static int buf_role_bad(ngtcp2_buf_role role) {
  return role > NGTCP2_BUF_ROLE_TX_DATAGRAM;
}

static int buf_bad_range(const ngtcp2_buf *buf) {
  if (buf == NULL || buf->begin == NULL || buf->end == NULL ||
      buf->pos == NULL || buf->last == NULL) {
    return 1;
  }

  return buf->begin > buf->pos || buf->pos > buf->last ||
         buf->last > buf->end;
}

void ngtcp2_buf_init(ngtcp2_buf *buf, uint8_t *begin, size_t len,
                     void *origin, ngtcp2_buf_role role, void *owner,
                     ngtcp2_buf_retain retain, ngtcp2_buf_release release) {
  *buf = (ngtcp2_buf){
    .begin = begin,
    .end = begin ? begin + len : NULL,
    .pos = begin,
    .last = begin,
    .origin = origin,
    .role = role,
    .owner = owner,
    .retain = retain,
    .release = release,
  };
}

void ngtcp2_buf_init_internal(ngtcp2_buf *buf, uint8_t *begin, size_t len) {
  ngtcp2_buf_init(buf, begin, len, NULL, NGTCP2_BUF_ROLE_INTERNAL, NULL, NULL,
                  NULL);
}

int ngtcp2_buf_validate(const ngtcp2_buf *buf, ngtcp2_buf_role role) {
  if (buf_bad_range(buf) || buf_role_bad(role) || buf_role_bad(buf->role) ||
      buf->role != role ||
      ((buf->owner != NULL || buf->retain != NULL || buf->release != NULL) &&
       !(buf->owner != NULL && buf->retain != NULL && buf->release != NULL))) {
    return NGTCP2_ERR_BUF_CONTRACT;
  }

  return 0;
}

int ngtcp2_buf_retain_owner(const ngtcp2_buf *buf) {
  if (buf == NULL || buf->owner == NULL || buf->retain == NULL ||
      buf->release == NULL) {
    return NGTCP2_ERR_BUF_CONTRACT;
  }

  if (buf->retain(buf->owner) != 0) {
    return NGTCP2_ERR_BUF_CONTRACT;
  }

  return 0;
}

void ngtcp2_buf_release_owner(ngtcp2_buf *buf) {
  if (buf == NULL) {
    return;
  }

  if (buf->owner && buf->release) {
    buf->release(buf->owner);
  }

  *buf = (ngtcp2_buf){0};
}

int ngtcp2_buf_slice(ngtcp2_buf *dest, const ngtcp2_buf *src, size_t off,
                     size_t len, ngtcp2_buf_role role) {
  ngtcp2_buf buf;
  int rv;

  if (dest == NULL || buf_bad_range(src) || off > ngtcp2_buf_len(src) ||
      len > ngtcp2_buf_len(src) - off || buf_role_bad(role)) {
    return NGTCP2_ERR_BUF_CONTRACT;
  }

  buf = *src;
  buf.pos = src->pos + off;
  buf.last = buf.pos + len;
  buf.role = role;

  if (src->owner || src->retain || src->release) {
    rv = ngtcp2_buf_retain_owner(src);
    if (rv != 0) {
      return rv;
    }
  }

  *dest = buf;

  return 0;
}

void ngtcp2_buf_move(ngtcp2_buf *dest, ngtcp2_buf *src) {
  *dest = *src;
  *src = (ngtcp2_buf){0};
}

void ngtcp2_buf_reset(ngtcp2_buf *buf) { buf->pos = buf->last = buf->begin; }

size_t ngtcp2_buf_len(const ngtcp2_buf *buf) {
  return (size_t)(buf->last - buf->pos);
}

size_t ngtcp2_buf_cap(const ngtcp2_buf *buf) {
  return (size_t)(buf->end - buf->begin);
}

void ngtcp2_buf_trunc(ngtcp2_buf *buf, size_t len) {
  if (ngtcp2_buf_len(buf) > len) {
    buf->last = buf->pos + len;
  }
}

int ngtcp2_buf_chain_new(ngtcp2_buf_chain **pbufchain, size_t len,
                         const ngtcp2_mem *mem) {
  *pbufchain = ngtcp2_mem_malloc(mem, sizeof(ngtcp2_buf_chain) + len);
  if (*pbufchain == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  (*pbufchain)->next = NULL;

  ngtcp2_buf_init_internal(&(*pbufchain)->buf,
                           (uint8_t *)(*pbufchain) +
                             sizeof(ngtcp2_buf_chain),
                           len);

  return 0;
}

void ngtcp2_buf_chain_del(ngtcp2_buf_chain *bufchain, const ngtcp2_mem *mem) {
  ngtcp2_mem_free(mem, bufchain);
}
