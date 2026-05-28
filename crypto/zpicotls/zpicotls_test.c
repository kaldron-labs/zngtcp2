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

  crypto->aead.native_handle = (void *)&ptls_openssl_aes128gcm;
  crypto->aead.max_overhead = ptls_openssl_aes128gcm.tag_size;
  noncelen = ngtcp2_crypto_packet_protection_ivlen(&crypto->aead);

  assert_int(0, ==,
             ngtcp2_crypto_aead_ctx_encrypt_init(
               &crypto->enc_ctx, &crypto->aead, key, noncelen));
  assert_int(0, ==,
             ngtcp2_crypto_aead_ctx_decrypt_init(
               &crypto->dec_ctx, &crypto->aead, key, noncelen));

  crypto->hp.native_handle = (void *)&ptls_openssl_aes128ecb;
  hp_ctx = ptls_cipher_new(&ptls_openssl_aes128ecb, 1, key);
  assert_not_null(hp_ctx);
  ptls_cipher_init(hp_ctx, NULL);
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
  static const uint8_t nonce[PTLS_MAX_IV_SIZE] = {0};
  const ngtcp2_crypto_ops *ops = ngtcp2_crypto_zpicotls_get_crypto_ops();
  zpicotls_test_crypto crypto;
  uint8_t pktbuf[128];
  uint8_t plaintext[32];
  uint8_t mask[NGTCP2_HP_SAMPLELEN] = {0};
  ngtcp2_buf pkt;
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
    pktbuf[payload_offset + i] = (uint8_t)(0xa0 + i);
  }
  memcpy(plaintext, pktbuf + payload_offset, plaintextlen);

  ngtcp2_buf_init(&pkt, pktbuf, sizeof(pktbuf), NGTCP2_BUF_ORIGIN_APPLICATION,
                  NGTCP2_BUF_DIR_TX, NGTCP2_BUF_PURPOSE_PACKET_TX, NULL, NULL,
                  NULL);
  pkt.last = pkt.pos + payload_offset + plaintextlen;

  assert_int(0, ==,
             ops->encrypt_pkt(&pkt, payload_offset, plaintextlen, &crypto.aead,
                              &crypto.enc_ctx, pktbuf, aadlen, nonce,
                              noncelen, &crypto.hp, &crypto.hp_ctx,
                              payload_offset + 4, mask, NULL));
  assert_ptr_equal(pktbuf + payload_offset + plaintextlen +
                     crypto.aead.max_overhead,
                   pkt.last);
  assert_false(is_zero(mask, NGTCP2_HP_MASKLEN));

  pkt.dir = NGTCP2_BUF_DIR_RX;
  pkt.purpose = NGTCP2_BUF_PURPOSE_PACKET_RX;

  assert_int(0, ==,
             ops->decrypt_pkt(&pkt, payload_offset,
                              plaintextlen + crypto.aead.max_overhead,
                              &crypto.aead, &crypto.dec_ctx, pktbuf, aadlen,
                              nonce, noncelen, NULL));
  assert_ptr_equal(pktbuf + payload_offset + plaintextlen, pkt.last);
  assert_memory_equal(plaintextlen, plaintext, pktbuf + payload_offset);

  free_crypto(&crypto);
}

void test_zpicotls_crypto_ops_packet_contract(void) {
  static const uint8_t nonce[PTLS_MAX_IV_SIZE] = {0};
  const ngtcp2_crypto_ops *ops = ngtcp2_crypto_zpicotls_get_crypto_ops();
  zpicotls_test_crypto crypto;
  uint8_t pktbuf[64] = {0};
  ngtcp2_buf pkt;
  size_t payload_offset = 8;
  size_t plaintextlen = 16;
  size_t aadlen = payload_offset;
  size_t noncelen;

  init_crypto(&crypto);
  noncelen = ngtcp2_crypto_packet_protection_ivlen(&crypto.aead);

  ngtcp2_buf_init(&pkt, pktbuf, sizeof(pktbuf), NGTCP2_BUF_ORIGIN_BORROWED,
                  NGTCP2_BUF_DIR_TX, NGTCP2_BUF_PURPOSE_PACKET_TX, NULL, NULL,
                  NULL);
  pkt.last = pkt.pos + payload_offset + plaintextlen;
  assert_int(NGTCP2_ERR_BUF_CONTRACT, ==,
             ops->encrypt_pkt(&pkt, payload_offset, plaintextlen, &crypto.aead,
                              &crypto.enc_ctx, pktbuf, aadlen, nonce,
                              noncelen, NULL, NULL, 0, NULL, NULL));

  ngtcp2_buf_init(&pkt, pktbuf, sizeof(pktbuf), NGTCP2_BUF_ORIGIN_APPLICATION,
                  NGTCP2_BUF_DIR_TX, NGTCP2_BUF_PURPOSE_CRYPTO_TX, NULL, NULL,
                  NULL);
  pkt.last = pkt.pos + payload_offset + plaintextlen;
  assert_int(NGTCP2_ERR_BUF_CONTRACT, ==,
             ops->encrypt_pkt(&pkt, payload_offset, plaintextlen, &crypto.aead,
                              &crypto.enc_ctx, pktbuf, aadlen, nonce,
                              noncelen, NULL, NULL, 0, NULL, NULL));

  ngtcp2_buf_init(&pkt, pktbuf, sizeof(pktbuf), NGTCP2_BUF_ORIGIN_BORROWED,
                  NGTCP2_BUF_DIR_RX, NGTCP2_BUF_PURPOSE_PACKET_RX, NULL, NULL,
                  NULL);
  pkt.last = pkt.pos + payload_offset + plaintextlen + crypto.aead.max_overhead;
  assert_int(NGTCP2_ERR_BUF_CONTRACT, ==,
             ops->decrypt_pkt(&pkt, payload_offset,
                              plaintextlen + crypto.aead.max_overhead,
                              &crypto.aead, &crypto.dec_ctx, pktbuf, aadlen,
                              nonce, noncelen, NULL));

  free_crypto(&crypto);
}

void test_zpicotls_hp_mask_op(void) {
  const ngtcp2_crypto_ops *ops = ngtcp2_crypto_zpicotls_get_crypto_ops();
  zpicotls_test_crypto crypto;
  uint8_t sample[NGTCP2_HP_SAMPLELEN];
  uint8_t mask[NGTCP2_HP_SAMPLELEN] = {0};
  size_t i;

  init_crypto(&crypto);

  for (i = 0; i < sizeof(sample); ++i) {
    sample[i] = (uint8_t)(0xc0 + i);
  }

  assert_int(0, ==,
             ops->hp_mask(mask, &crypto.hp, &crypto.hp_ctx, sample, NULL));
  assert_false(is_zero(mask, NGTCP2_HP_MASKLEN));

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
