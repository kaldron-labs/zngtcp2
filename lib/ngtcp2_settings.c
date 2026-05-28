/*
 * ngtcp2
 *
 * Copyright (c) 2024 ngtcp2 contributors
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
#include "ngtcp2_settings.h"

#include <string.h>
#include <assert.h>

void ngtcp2_settings_default_versioned(int settings_version,
                                       ngtcp2_settings *settings) {
  assert(settings_version == NGTCP2_SETTINGS_VERSION);

  memset(settings, 0, sizeof(*settings));

  settings->glitch_ratelim_burst = NGTCP2_DEFAULT_GLITCH_RATELIM_BURST;
  settings->glitch_ratelim_rate = NGTCP2_DEFAULT_GLITCH_RATELIM_RATE;
  settings->cc_algo = NGTCP2_CC_ALGO_CUBIC;
  settings->initial_rtt = NGTCP2_DEFAULT_INITIAL_RTT;
  settings->ack_thresh = 2;
  settings->max_tx_udp_payload_size = 1500 - 48;
  settings->handshake_timeout = UINT64_MAX;
}

const ngtcp2_settings *
ngtcp2_settings_convert_to_latest(ngtcp2_settings *dest, int settings_version,
                                  const ngtcp2_settings *src) {
  (void)dest;

  assert(settings_version == NGTCP2_SETTINGS_VERSION);

  return src;
}

size_t ngtcp2_settingslen_version(int settings_version) {
  assert(settings_version == NGTCP2_SETTINGS_VERSION);

  return sizeof(ngtcp2_settings);
}
