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
#ifndef NGTCP2_SETTINGS_H
#define NGTCP2_SETTINGS_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <zngtcp2/zngtcp2.h>

/* NGTCP2_DEFAULT_GLITCH_RATELIM_BURST is the maximum number of tokens
   in glitch rate limiter.  It is also the initial value. */
#define NGTCP2_DEFAULT_GLITCH_RATELIM_BURST 10000
/* NGTCP2_DEFAULT_GLITCH_RATELIM_RATE is the rate of tokens generated
   per second for glitch rate limiter. */
#define NGTCP2_DEFAULT_GLITCH_RATELIM_RATE 330

/*
 * ngtcp2_settings_convert_to_latest validates that |src| uses
 * NGTCP2_SETTINGS_VERSION and returns |src|.
 *
 * |dest| is unused and exists only for the versioned constructor call
 * path.
 */
const ngtcp2_settings *
ngtcp2_settings_convert_to_latest(ngtcp2_settings *dest, int settings_version,
                                  const ngtcp2_settings *src);

/*
 * ngtcp2_settingslen_version returns sizeof(ngtcp2_settings) for
 * NGTCP2_SETTINGS_VERSION.
 */
size_t ngtcp2_settingslen_version(int settings_version);

#endif /* !defined(NGTCP2_SETTINGS_H) */
