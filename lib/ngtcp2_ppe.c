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
#include "ngtcp2_ppe.h"

#include <string.h>
#include <assert.h>

#include "ngtcp2_str.h"
#include "ngtcp2_conv.h"
#include "ngtcp2_macro.h"

void ngtcp2_ppe_init(ngtcp2_ppe *ppe, uint8_t *out, size_t outlen,
                     size_t dgram_offset, ngtcp2_crypto_cc *cc) {
  ngtcp2_buf_init(&ppe->buf, out, outlen, ((void *)(uintptr_t)1),
                  NGTCP2_BUF_ROLE_TX_PACKET, NULL, NULL,
                  NULL);
  ngtcp2_buf_init(&ppe->plain, ppe->plain_storage,
                  sizeof(ppe->plain_storage), NULL, NGTCP2_BUF_ROLE_TX_CONTROL,
                  NULL, NULL, NULL);

  ppe->dgram_offset = dgram_offset;
  ppe->hdlen = 0;
  ppe->payloadlen = 0;
  ppe->plainv_offset = 0;
  ppe->plainvcnt = 0;
  ppe->len_offset = 0;
  ppe->pkt_num_offset = 0;
  ppe->pkt_numlen = 0;
  ppe->pkt_num = 0;
  ppe->cc = cc;
}

/*
 * ppe_sample_offset returns the offset to sample for packet number
 * encryption.
 */
static size_t ppe_sample_offset(ngtcp2_ppe *ppe) {
  return ppe->pkt_num_offset + 4;
}

static size_t ppe_pkt_len(const ngtcp2_ppe *ppe) {
  return ppe->hdlen + ppe->payloadlen;
}

static size_t ppe_packet_plain_left(const ngtcp2_ppe *ppe) {
  const ngtcp2_buf *buf = &ppe->buf;
  size_t left;

  if (ppe->hdlen > (size_t)(buf->end - buf->pos)) {
    return 0;
  }

  left = (size_t)(buf->end - (buf->pos + ppe->hdlen));
  if (left <= ppe->cc->aead.max_overhead) {
    return 0;
  }

  left -= ppe->cc->aead.max_overhead;
  if (left <= ppe->payloadlen) {
    return 0;
  }

  return left - ppe->payloadlen;
}

static int ppe_add_plainv(ngtcp2_ppe *ppe, const uint8_t *base, size_t len,
                          const ngtcp2_buf *source) {
  if (len == 0) {
    return 0;
  }
  if (ppe->plainvcnt == NGTCP2_PPE_MAX_PLAINV) {
    return NGTCP2_ERR_BUF_CONTRACT;
  }

  ppe->plainv[ppe->plainvcnt++] = (ngtcp2_crypto_vec){
    .base = base,
    .len = len,
    .source = source,
  };

  return 0;
}

static int ppe_flush_control(ngtcp2_ppe *ppe) {
  size_t len = ngtcp2_buf_len(&ppe->plain) - ppe->plainv_offset;
  int rv;

  rv = ppe_add_plainv(ppe, ppe->plain.pos + ppe->plainv_offset, len,
                      &ppe->plain);
  if (rv != 0) {
    return rv;
  }

  ppe->plainv_offset += len;

  return 0;
}

static int ppe_sync_legacy_payload(ngtcp2_ppe *ppe) {
  size_t pktlen = ngtcp2_buf_len(&ppe->buf);
  size_t len;

  if (ppe->payloadlen || pktlen <= ppe->hdlen) {
    return 0;
  }

  len = pktlen - ppe->hdlen;
  if (len > ngtcp2_buf_left(&ppe->plain)) {
    return NGTCP2_ERR_NOBUF;
  }

  memcpy(ppe->plain.last, ppe->buf.pos + ppe->hdlen, len);
  ppe->plain.last += len;
  ppe->payloadlen = len;
  ppe->buf.last = ppe->buf.pos + ppe->hdlen;

  return 0;
}

static ngtcp2_ssize ppe_encode_stream_frame_hd(uint8_t *out, size_t outlen,
                                               ngtcp2_stream *fr,
                                               size_t datalen) {
  size_t len = 1;
  uint8_t flags = NGTCP2_STREAM_LEN_BIT;
  uint8_t *p;

  if (fr->fin) {
    flags |= NGTCP2_STREAM_FIN_BIT;
  }

  if (fr->offset) {
    flags |= NGTCP2_STREAM_OFF_BIT;
    len += ngtcp2_put_uvarintlen(fr->offset);
  }

  len += ngtcp2_put_uvarintlen((uint64_t)fr->stream_id);
  len += ngtcp2_put_uvarintlen(datalen);

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;
  *p++ = flags | NGTCP2_FRAME_STREAM;
  fr->flags = flags;
  p = ngtcp2_put_uvarint(p, (uint64_t)fr->stream_id);
  if (fr->offset) {
    p = ngtcp2_put_uvarint(p, fr->offset);
  }
  p = ngtcp2_put_uvarint(p, datalen);

  assert((size_t)(p - out) == len);

  return (ngtcp2_ssize)len;
}

static ngtcp2_ssize ppe_encode_datagram_frame_hd(uint8_t *out, size_t outlen,
                                                 const ngtcp2_datagram *fr,
                                                 size_t datalen) {
  size_t len = 1 + ngtcp2_put_uvarintlen(datalen);
  uint8_t *p;

  assert(fr->type == NGTCP2_FRAME_DATAGRAM_LEN);

  if (outlen < len) {
    return NGTCP2_ERR_NOBUF;
  }

  p = out;
  *p++ = (uint8_t)fr->type;
  p = ngtcp2_put_uvarint(p, datalen);

  assert((size_t)(p - out) == len);

  return (ngtcp2_ssize)len;
}

int ngtcp2_ppe_encode_hd(ngtcp2_ppe *ppe, const ngtcp2_pkt_hd *hd) {
  ngtcp2_ssize rv;
  ngtcp2_buf *buf = &ppe->buf;
  size_t buf_left = ngtcp2_buf_left(buf);
  ngtcp2_crypto_cc *cc = ppe->cc;

  if (buf_left <= cc->aead.max_overhead) {
    return NGTCP2_ERR_NOBUF;
  }

  if (hd->flags & NGTCP2_PKT_FLAG_LONG_FORM) {
    ppe->len_offset = 1 + 4 + 1 + hd->dcid.datalen + 1 + hd->scid.datalen;

    if (hd->type == NGTCP2_PKT_INITIAL) {
      ppe->len_offset += ngtcp2_put_uvarintlen(hd->tokenlen) + hd->tokenlen;
    }

    ppe->pkt_num_offset = ppe->len_offset + NGTCP2_PKT_LENGTHLEN;

    rv = ngtcp2_pkt_encode_hd_long(buf->last, buf_left - cc->aead.max_overhead,
                                   hd);
  } else {
    ppe->pkt_num_offset = 1 + hd->dcid.datalen;

    rv = ngtcp2_pkt_encode_hd_short(buf->last, buf_left - cc->aead.max_overhead,
                                    hd);
  }

  if (rv < 0) {
    return (int)rv;
  }

  buf->last += rv;

  if (ngtcp2_buf_cap(buf) < ppe_sample_offset(ppe) + NGTCP2_HP_SAMPLELEN) {
    return NGTCP2_ERR_NOBUF;
  }

  ppe->pkt_numlen = hd->pkt_numlen;
  ppe->hdlen = (size_t)rv;
  ppe->pkt_num = hd->pkt_num;

  return 0;
}

int ngtcp2_ppe_encode_frame(ngtcp2_ppe *ppe, ngtcp2_frame *fr) {
  ngtcp2_ssize rv;
  ngtcp2_buf *plain = &ppe->plain;
  size_t buf_left =
    ngtcp2_min(ngtcp2_buf_left(plain), ppe_packet_plain_left(ppe));
  size_t packet_left;
  size_t datalen;

  if (buf_left == 0) {
    return NGTCP2_ERR_NOBUF;
  }

  if (fr->hd.type == NGTCP2_FRAME_STREAM && fr->stream.txbuf_present) {
    datalen = ngtcp2_buf_len(&fr->stream.txbuf);
    packet_left = ppe_packet_plain_left(ppe);
    if (datalen > packet_left) {
      return NGTCP2_ERR_NOBUF;
    }

    rv = ppe_encode_stream_frame_hd(plain->last, buf_left, &fr->stream,
                                    datalen);
    if (rv < 0) {
      return (int)rv;
    }
    if ((size_t)rv > packet_left - datalen) {
      return NGTCP2_ERR_NOBUF;
    }

    plain->last += rv;
    ppe->payloadlen += (size_t)rv + datalen;

    rv = ppe_flush_control(ppe);
    if (rv != 0) {
      return (int)rv;
    }

    return ppe_add_plainv(ppe, fr->stream.txbuf.pos, datalen,
                          &fr->stream.txbuf);
  }

  if (fr->hd.type == NGTCP2_FRAME_DATAGRAM_LEN &&
      fr->datagram.txbuf_present) {
    datalen = ngtcp2_buf_len(&fr->datagram.txbuf);
    packet_left = ppe_packet_plain_left(ppe);
    if (datalen > packet_left) {
      return NGTCP2_ERR_NOBUF;
    }

    rv = ppe_encode_datagram_frame_hd(plain->last, buf_left, &fr->datagram,
                                      datalen);
    if (rv < 0) {
      return (int)rv;
    }
    if ((size_t)rv > packet_left - datalen) {
      return NGTCP2_ERR_NOBUF;
    }

    plain->last += rv;
    ppe->payloadlen += (size_t)rv + datalen;

    rv = ppe_flush_control(ppe);
    if (rv != 0) {
      return (int)rv;
    }

    return ppe_add_plainv(ppe, fr->datagram.txbuf.pos, datalen,
                          &fr->datagram.txbuf);
  }

  rv = ngtcp2_pkt_encode_frame(plain->last, buf_left, fr);
  if (rv < 0) {
    return (int)rv;
  }

  plain->last += rv;
  ppe->payloadlen += (size_t)rv;

  return 0;
}

ngtcp2_ssize ngtcp2_ppe_final(ngtcp2_ppe *ppe, const uint8_t **ppkt) {
  ngtcp2_buf *buf = &ppe->buf;
  ngtcp2_crypto_cc *cc = ppe->cc;
  size_t payloadlen;
  uint8_t mask[NGTCP2_HP_SAMPLELEN];
  ngtcp2_buf aad, nonce, maskbuf;
  uint8_t *p;
  size_t i;
  int rv;

  assert(cc->ops.protect_pkt || cc->buf_stats);

  rv = ppe_sync_legacy_payload(ppe);
  if (rv != 0) {
    return rv;
  }
  payloadlen = ppe->payloadlen;

  if (ppe->len_offset) {
    ngtcp2_put_uvarint30(
      buf->begin + ppe->len_offset,
      (uint16_t)(payloadlen + ppe->pkt_numlen + cc->aead.max_overhead));
  }

  ngtcp2_crypto_create_nonce(ppe->nonce, cc->ckm->iv.base, cc->ckm->iv.len,
                             ppe->pkt_num);
  ngtcp2_buf_init(&aad, buf->begin, ppe->hdlen, NULL,
                  NGTCP2_BUF_ROLE_TX_PACKET, NULL, NULL,
                  NULL);
  aad.last = aad.end;
  ngtcp2_buf_init(&nonce, ppe->nonce, cc->ckm->iv.len,
                  NULL, NGTCP2_BUF_ROLE_INTERNAL, NULL, NULL, NULL);
  nonce.last = nonce.end;
  ngtcp2_buf_init(&maskbuf, mask, sizeof(mask), NULL,
                  NGTCP2_BUF_ROLE_INTERNAL, NULL, NULL,
                  NULL);

  if (!cc->ops.protect_pkt) {
    if (cc->buf_stats) {
      ++cc->buf_stats->encrypt_source_to_dest_failure;
      ++cc->buf_stats->buf_contract_failure;
    }

    return NGTCP2_ERR_BUF_CONTRACT;
  }

  rv = ppe_flush_control(ppe);
  if (rv != 0) {
    if (cc->buf_stats) {
      ++cc->buf_stats->encrypt_source_to_dest_failure;
      ++cc->buf_stats->buf_contract_failure;
    }
    return rv;
  }

  rv = cc->ops.protect_pkt(buf, ppe->hdlen, ppe->plainv, ppe->plainvcnt,
                           &cc->aead,
                           &cc->ckm->aead_ctx, &aad, &nonce, &cc->hp,
                           &cc->hp_ctx, ppe_sample_offset(ppe), &maskbuf,
                           cc->ops_ctx);
  if (rv != 0) {
    if (cc->buf_stats) {
      ++cc->buf_stats->encrypt_source_to_dest_failure;
    }
    return rv == NGTCP2_ERR_BUF_CONTRACT ? rv : NGTCP2_ERR_CALLBACK_FAILURE;
  }
  if (ngtcp2_buf_len(&maskbuf) < NGTCP2_HP_MASKLEN) {
    if (cc->buf_stats) {
      ++cc->buf_stats->encrypt_source_to_dest_failure;
      ++cc->buf_stats->buf_contract_failure;
    }
    return NGTCP2_ERR_BUF_CONTRACT;
  }

  if (cc->buf_stats) {
    ++cc->buf_stats->encrypt_source_to_dest_success;
  }

  p = buf->begin;
  if (*p & NGTCP2_HEADER_FORM_BIT) {
    *p = (uint8_t)(*p ^ (mask[0] & 0x0FU));
  } else {
    *p = (uint8_t)(*p ^ (mask[0] & 0x1FU));
  }

  p = buf->begin + ppe->pkt_num_offset;
  for (i = 0; i < ppe->pkt_numlen; ++i) {
    *(p + i) ^= mask[i + 1];
  }

  if (ppkt != NULL) {
    *ppkt = buf->begin;
  }

  return (ngtcp2_ssize)ngtcp2_buf_len(buf);
}

size_t ngtcp2_ppe_left(const ngtcp2_ppe *ppe) {
  return ppe_packet_plain_left(ppe);
}

size_t ngtcp2_ppe_padding_size(ngtcp2_ppe *ppe, size_t n) {
  ngtcp2_crypto_cc *cc = ppe->cc;
  ngtcp2_buf *plain = &ppe->plain;
  size_t pktlen;
  size_t len = 0;
  size_t min_pktlen;
  size_t left;
  uint8_t *pkt_padding;

  if (ppe_sync_legacy_payload(ppe) != 0) {
    return 0;
  }

  pktlen = ppe_pkt_len(ppe) + cc->aead.max_overhead;
  left = ngtcp2_min(ngtcp2_buf_left(plain), ppe_packet_plain_left(ppe));

  n = ngtcp2_min(n, ppe_pkt_len(ppe) + left + cc->aead.max_overhead);
  if (pktlen < n) {
    len = n - pktlen;
  }

  /* Ensure header protection sample */
  min_pktlen = ppe_sample_offset(ppe) + NGTCP2_HP_SAMPLELEN;
  if (pktlen < min_pktlen) {
    len = ngtcp2_max(len, min_pktlen - pktlen);
  }

  /* ngtcp2_ppe_encode_hd ensures that the buffer has enough capacity
     for the padding required for header protection sample. */
  assert(left >= len);

  if (len == 0) {
    return 0;
  }

  pkt_padding = ppe->buf.pos + ppe_pkt_len(ppe);
  if (len <= (size_t)(ppe->buf.end - pkt_padding)) {
    ngtcp2_setmem(pkt_padding, 0, len);
    if (ppe->buf.last < pkt_padding + len) {
      ppe->buf.last = pkt_padding + len;
    }
  }
  plain->last = ngtcp2_setmem(plain->last, 0, len);
  ppe->payloadlen += len;

  return len;
}

size_t ngtcp2_ppe_dgram_padding(ngtcp2_ppe *ppe) {
  return ngtcp2_ppe_dgram_padding_size(ppe, NGTCP2_MAX_UDP_PAYLOAD_SIZE);
}

size_t ngtcp2_ppe_dgram_padding_size(ngtcp2_ppe *ppe, size_t n) {
  ngtcp2_crypto_cc *cc = ppe->cc;
  ngtcp2_buf *plain = &ppe->plain;
  size_t pktlen;
  size_t dgramlen;
  size_t len;
  size_t min_pktlen;
  size_t left;
  uint8_t *pkt_padding;

  if (ppe_sync_legacy_payload(ppe) != 0) {
    return 0;
  }

  pktlen = ppe_pkt_len(ppe) + cc->aead.max_overhead;
  dgramlen = ppe->dgram_offset + pktlen;
  left = ngtcp2_min(ngtcp2_buf_left(plain), ppe_packet_plain_left(ppe));

  n = ngtcp2_min(n, ppe->dgram_offset + ppe_pkt_len(ppe) + left +
                      cc->aead.max_overhead);

  if (dgramlen < n) {
    len = n - dgramlen;
  } else {
    len = 0;
  }

  /* Ensure header protection sample */
  min_pktlen = ppe_sample_offset(ppe) + NGTCP2_HP_SAMPLELEN;
  if (pktlen < min_pktlen) {
    len = ngtcp2_max(len, min_pktlen - pktlen);
  }

  /* ngtcp2_ppe_encode_hd ensures that the buffer has enough capacity
     for the padding required for header protection sample. */
  assert(left >= len);

  if (len == 0) {
    return 0;
  }

  pkt_padding = ppe->buf.pos + ppe_pkt_len(ppe);
  if (len <= (size_t)(ppe->buf.end - pkt_padding)) {
    ngtcp2_setmem(pkt_padding, 0, len);
    if (ppe->buf.last < pkt_padding + len) {
      ppe->buf.last = pkt_padding + len;
    }
  }
  plain->last = ngtcp2_setmem(plain->last, 0, len);
  ppe->payloadlen += len;

  return len;
}
