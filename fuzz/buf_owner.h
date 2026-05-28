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
#ifndef FUZZ_BUF_OWNER_H
#define FUZZ_BUF_OWNER_H

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

struct FuzzBufOwner {
  std::vector<uint8_t> data;
  size_t retaincnt = 0;
  size_t releasecnt = 0;
};

using FuzzBufOwners = std::vector<std::unique_ptr<FuzzBufOwner>>;

inline int fuzz_buf_retain(void *owner) {
  ++static_cast<FuzzBufOwner *>(owner)->retaincnt;

  return 0;
}

inline void fuzz_buf_release(void *owner) {
  ++static_cast<FuzzBufOwner *>(owner)->releasecnt;
}

inline FuzzBufOwner *fuzz_buf_owner_add(FuzzBufOwners &owners,
                                        const uint8_t *data, size_t datalen) {
  auto owner = std::make_unique<FuzzBufOwner>();
  auto result = owner.get();

  if (datalen) {
    owner->data.assign(data, data + datalen);
  }

  owners.push_back(std::move(owner));

  return result;
}

inline void fuzz_buf_owners_check_balanced(const FuzzBufOwners &owners) {
  for (const auto &owner : owners) {
    assert(owner->retaincnt == owner->releasecnt);
  }
}

#endif /* !defined(FUZZ_BUF_OWNER_H) */
