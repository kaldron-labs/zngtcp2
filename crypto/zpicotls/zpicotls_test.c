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
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#define MUNIT_ENABLE_ASSERT_ALIASES

#include "munit.h"

#include <string.h>

#include <zngtcp2/ngtcp2_crypto.h>
#include <zngtcp2/zngtcp2.h>
#include <zngtcp2/zngtcp2_crypto_zpicotls.h>

#include <zpicotls.h>
#include <zpicotls/openssl.h>

#include "../shared.h"

typedef struct zpicotls_test_crypto {
  ngtcp2_crypto_aead aead;
  ngtcp2_crypto_aead_ctx enc_ctx;
  ngtcp2_crypto_aead_ctx dec_ctx;
  ngtcp2_crypto_cipher hp;
  ngtcp2_crypto_cipher_ctx hp_ctx;
} zpicotls_test_crypto;

static void init_crypto(zpicotls_test_crypto *crypto) {
  static const uint8_t key[16] = {0};
  size_t noncelen;
  ptls_cipher_context_t *hp_ctx;

  memset(crypto, 0, sizeof(*crypto));

  ngtcp2_crypto_aead_init(&crypto->aead, (void *)&ptls_openssl_aes128gcm);
  noncelen = ngtcp2_crypto_packet_protection_ivlen(&crypto->aead);

  assert_int(0, ==,
             ngtcp2_crypto_aead_ctx_encrypt_init(
               &crypto->enc_ctx, &crypto->aead, key, noncelen));
  assert_int(0, ==,
             ngtcp2_crypto_aead_ctx_decrypt_init(
               &crypto->dec_ctx, &crypto->aead, key, noncelen));

  crypto->hp.native_handle = (void *)&ptls_openssl_aes128ctr;
  hp_ctx = ptls_cipher_new(&ptls_openssl_aes128ctr, 1, key);
  assert_not_null(hp_ctx);
  crypto->hp_ctx.native_handle = hp_ctx;
}

static void free_crypto(zpicotls_test_crypto *crypto) {
  if (crypto->hp_ctx.native_handle) {
    ptls_cipher_free(crypto->hp_ctx.native_handle);
  }
  ngtcp2_crypto_aead_ctx_free(&crypto->dec_ctx);
  ngtcp2_crypto_aead_ctx_free(&crypto->enc_ctx);
}

static int is_zero(const uint8_t *data, size_t datalen) {
  size_t i;

  for (i = 0; i < datalen; ++i) {
    if (data[i]) {
      return 0;
    }
  }

  return 1;
}

munit_void_test_decl(test_zpicotls_crypto_ops_packet_roundtrip)
munit_void_test_decl(test_zpicotls_crypto_ops_packet_contract)
munit_void_test_decl(test_zpicotls_hp_mask_op)
munit_void_test_decl(test_zpicotls_buffer_hook_rejects_external_origin)

void test_zpicotls_crypto_ops_packet_roundtrip(void) {
  const ngtcp2_crypto_ops *ops = ngtcp2_crypto_zpicotls_get_crypto_ops();
  zpicotls_test_crypto crypto;
  uint8_t pktbuf[128];
  uint8_t nonce[PTLS_MAX_IV_SIZE] = {0};
  uint8_t plaintext[32];
  uint8_t rxplainbuf[32];
  uint8_t mask[NGTCP2_HP_SAMPLELEN] = {0};
  uint8_t expected_mask[NGTCP2_HP_SAMPLELEN] = {0};
  ngtcp2_buf pkt, aadbuf, noncebuf, hp_maskbuf;
  ngtcp2_buf samplebuf, maskbuf, rxplain;
  ngtcp2_crypto_vec plainv;
  size_t payload_offset = 8;
  size_t plaintextlen = sizeof(plaintext);
  size_t aadlen = payload_offset;
  size_t noncelen;
  size_t i;

  assert_not_null(ops);
  init_crypto(&crypto);
  noncelen = ngtcp2_crypto_packet_protection_ivlen(&crypto.aead);

  memset(pktbuf, 0, sizeof(pktbuf));
  for (i = 0; i < aadlen; ++i) {
    pktbuf[i] = (uint8_t)(0x40 + i);
  }
  for (i = 0; i < plaintextlen; ++i) {
    plaintext[i] = (uint8_t)(0xa0 + i);
  }

  ngtcp2_buf_init(&pkt, pktbuf, sizeof(pktbuf), ((void *)(uintptr_t)1),
                  NGTCP2_BUF_ROLE_TX_PACKET, NULL, NULL,
                  NULL);
  pkt.last = pkt.pos + payload_offset + plaintextlen;
  ngtcp2_buf_init(&aadbuf, pktbuf, aadlen, NULL,
                  NGTCP2_BUF_ROLE_TX_PACKET, NULL, NULL,
                  NULL);
  aadbuf.last = aadbuf.end;
  ngtcp2_buf_init(&noncebuf, nonce, noncelen, NULL,
                  NGTCP2_BUF_ROLE_INTERNAL, NULL, NULL,
                  NULL);
  noncebuf.last = noncebuf.end;
  ngtcp2_buf_init(&hp_maskbuf, mask, sizeof(mask), NULL,
                  NGTCP2_BUF_ROLE_INTERNAL, NULL, NULL,
                  NULL);
  plainv = (ngtcp2_crypto_vec){
    .base = plaintext,
    .len = plaintextlen,
  };

  assert_int(0, ==,
             ops->protect_pkt(&pkt, payload_offset, &plainv, 1, &crypto.aead,
                              &crypto.enc_ctx, &aadbuf, &noncebuf, &crypto.hp,
                              &crypto.hp_ctx, payload_offset + 4, &hp_maskbuf,
                              NULL));
  assert_ptr_equal(pktbuf + payload_offset + plaintextlen +
                     crypto.aead.max_overhead,
                   pkt.last);
  assert_ptr_equal(mask + NGTCP2_HP_SAMPLELEN, hp_maskbuf.last);
  assert_false(is_zero(mask, NGTCP2_HP_MASKLEN));

  ngtcp2_buf_init(&samplebuf, pktbuf + payload_offset + 4,
                  NGTCP2_HP_SAMPLELEN, NULL,
                  NGTCP2_BUF_ROLE_TX_PACKET, NULL, NULL,
                  NULL);
  samplebuf.last = samplebuf.end;
  ngtcp2_buf_init(&maskbuf, expected_mask, sizeof(expected_mask),
                  NULL, NGTCP2_BUF_ROLE_INTERNAL, NULL, NULL, NULL);

  assert_int(0, ==,
             ops->hp_mask(&maskbuf, &crypto.hp, &crypto.hp_ctx, &samplebuf,
                          NULL));
  assert_memory_equal(NGTCP2_HP_MASKLEN, expected_mask, mask);

  pkt.role = NGTCP2_BUF_ROLE_RX_PACKET;
  ngtcp2_buf_init(&rxplain, rxplainbuf, sizeof(rxplainbuf), NULL,
                  NGTCP2_BUF_ROLE_RX_STREAM, NULL, NULL, NULL);
  ngtcp2_buf_init(&aadbuf, pktbuf, aadlen, NULL,
                  NGTCP2_BUF_ROLE_RX_PACKET, NULL, NULL,
                  NULL);
  aadbuf.last = aadbuf.end;
  assert_int(0, ==,
             ops->unprotect_pkt(&rxplain, &pkt, payload_offset,
                              plaintextlen + crypto.aead.max_overhead,
                              &crypto.aead, &crypto.dec_ctx, &aadbuf,
                              &noncebuf, NULL));
  assert_ptr_equal(rxplainbuf + plaintextlen, rxplain.last);
  assert_memory_equal(plaintextlen, plaintext, rxplainbuf);

  free_crypto(&crypto);
}

void test_zpicotls_crypto_ops_packet_contract(void) {
  const ngtcp2_crypto_ops *ops = ngtcp2_crypto_zpicotls_get_crypto_ops();
  zpicotls_test_crypto crypto;
  uint8_t pktbuf[64] = {0};
  uint8_t plaintext[16] = {0};
  uint8_t rxplainbuf[16] = {0};
  uint8_t nonce[PTLS_MAX_IV_SIZE] = {0};
  ngtcp2_buf pkt, aadbuf, noncebuf, rxplain;
  ngtcp2_crypto_vec plainv;
  size_t payload_offset = 8;
  size_t plaintextlen = 16;
  size_t aadlen = payload_offset;
  size_t noncelen;

  init_crypto(&crypto);
  noncelen = ngtcp2_crypto_packet_protection_ivlen(&crypto.aead);
  ngtcp2_buf_init(&aadbuf, pktbuf, aadlen, NULL,
                  NGTCP2_BUF_ROLE_TX_PACKET, NULL, NULL,
                  NULL);
  aadbuf.last = aadbuf.end;
  ngtcp2_buf_init(&noncebuf, nonce, noncelen, NULL,
                  NGTCP2_BUF_ROLE_INTERNAL, NULL, NULL,
                  NULL);
  noncebuf.last = noncebuf.end;
  plainv = (ngtcp2_crypto_vec){
    .base = plaintext,
    .len = plaintextlen,
  };

  ngtcp2_buf_init(&pkt, pktbuf, sizeof(pktbuf), NULL,
                  NGTCP2_BUF_ROLE_TX_PACKET, NULL, NULL,
                  NULL);
  pkt.last = pkt.pos + payload_offset + plaintextlen;
  assert_int(0, ==,
             ops->protect_pkt(&pkt, payload_offset, &plainv, 1, &crypto.aead,
                              &crypto.enc_ctx, &aadbuf, &noncebuf, NULL, NULL,
                              0, NULL, NULL));

  ngtcp2_buf_init(&pkt, pktbuf, sizeof(pktbuf), ((void *)(uintptr_t)1),
                  NGTCP2_BUF_ROLE_TX_CONTROL, NULL, NULL,
                  NULL);
  pkt.last = pkt.pos + payload_offset + plaintextlen;
  assert_int(NGTCP2_ERR_BUF_CONTRACT, ==,
             ops->protect_pkt(&pkt, payload_offset, &plainv, 1, &crypto.aead,
                              &crypto.enc_ctx, &aadbuf, &noncebuf, NULL, NULL,
                              0, NULL, NULL));

  ngtcp2_buf_init(&pkt, pktbuf, sizeof(pktbuf), NULL,
                  NGTCP2_BUF_ROLE_RX_PACKET, NULL, NULL,
                  NULL);
  pkt.last = pkt.pos + payload_offset + plaintextlen + crypto.aead.max_overhead;
  ngtcp2_buf_init(&aadbuf, pktbuf, aadlen, NULL,
                  NGTCP2_BUF_ROLE_RX_PACKET, NULL, NULL,
                  NULL);
  aadbuf.last = aadbuf.end;
  ngtcp2_buf_init(&rxplain, rxplainbuf, sizeof(rxplainbuf), NULL,
                  NGTCP2_BUF_ROLE_RX_STREAM, NULL, NULL, NULL);
  noncebuf.role = NGTCP2_BUF_ROLE_TX_CONTROL;
  assert_int(NGTCP2_ERR_BUF_CONTRACT, ==,
             ops->unprotect_pkt(&rxplain, &pkt, payload_offset,
                              plaintextlen + crypto.aead.max_overhead,
                              &crypto.aead, &crypto.dec_ctx, &aadbuf,
                              &noncebuf, NULL));

  free_crypto(&crypto);
}

void test_zpicotls_hp_mask_op(void) {
  const ngtcp2_crypto_ops *ops = ngtcp2_crypto_zpicotls_get_crypto_ops();
  zpicotls_test_crypto crypto;
  uint8_t sample[NGTCP2_HP_SAMPLELEN];
  uint8_t mask[NGTCP2_HP_SAMPLELEN] = {0};
  ngtcp2_buf samplebuf, maskbuf;
  size_t i;

  init_crypto(&crypto);

  for (i = 0; i < sizeof(sample); ++i) {
    sample[i] = (uint8_t)(0xc0 + i);
  }

  ngtcp2_buf_init(&samplebuf, sample, sizeof(sample),
                  NULL, NGTCP2_BUF_ROLE_RX_PACKET, NULL, NULL, NULL);
  samplebuf.last = samplebuf.end;
  ngtcp2_buf_init(&maskbuf, mask, sizeof(mask), NULL,
                  NGTCP2_BUF_ROLE_INTERNAL, NULL, NULL,
                  NULL);

  assert_int(0, ==,
             ops->hp_mask(&maskbuf, &crypto.hp, &crypto.hp_ctx, &samplebuf,
                          NULL));
  assert_false(is_zero(mask, NGTCP2_HP_MASKLEN));

  samplebuf.role = NGTCP2_BUF_ROLE_RX_STREAM;
  assert_int(NGTCP2_ERR_BUF_CONTRACT, ==,
             ops->hp_mask(&maskbuf, &crypto.hp, &crypto.hp_ctx, &samplebuf,
                          NULL));

  free_crypto(&crypto);
}

void test_zpicotls_buffer_hook_rejects_external_origin(void) {
  ngtcp2_crypto_zpicotls_ctx cptls;
  ptls_buffer_t buf;
  uint8_t smallbuf[1] = {0};

  ngtcp2_crypto_zpicotls_ctx_init(&cptls);
  ptls_buffer_init_tx(&buf, smallbuf, sizeof(smallbuf));
  buf.origin = &cptls;

  assert_int(PTLS_ERROR_NO_MEMORY, ==,
             ptls_buffer_reserve(&buf, sizeof(smallbuf) + 1, 1));
  assert_ptr_equal(smallbuf, buf.base);
  assert_size(sizeof(smallbuf), ==, buf.capacity);
  assert_false(buf.is_allocated);

  buf.origin = NULL;
  ptls_buffer_dispose(&buf);
}

static const MunitTest tests[] = {
  munit_void_test(test_zpicotls_crypto_ops_packet_roundtrip),
  munit_void_test(test_zpicotls_crypto_ops_packet_contract),
  munit_void_test(test_zpicotls_hp_mask_op),
  munit_void_test(test_zpicotls_buffer_hook_rejects_external_origin),
  munit_test_end(),
};

static const MunitSuite suite = {
  .prefix = "/zpicotls",
  .tests = tests,
  .iterations = 1,
};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
