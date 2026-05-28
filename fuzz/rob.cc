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
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <memory>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#ifdef __cplusplus
extern "C" {
#endif // defined(__cplusplus)

#include "ngtcp2_reorder.h"

#ifdef __cplusplus
}
#endif // defined(__cplusplus)

namespace {
struct BufOwner {
  std::vector<uint8_t> data;
  size_t retaincnt;
  size_t releasecnt;
};

struct ReleaseState {
  size_t allocator_releasecnt;
};

int retain_buf(void *owner) {
  ++static_cast<BufOwner *>(owner)->retaincnt;

  return 0;
}

void release_buf(void *owner) {
  ++static_cast<BufOwner *>(owner)->releasecnt;
}

void release_reorder_buf(ngtcp2_buf *buf, int allocator_owned,
                         void *user_data) {
  auto state = static_cast<ReleaseState *>(user_data);

  if (allocator_owned) {
    ++state->allocator_releasecnt;
    return;
  }

  ngtcp2_buf_release_owner(buf);
}

void check_owners_balanced(
  const std::vector<std::unique_ptr<BufOwner>> &owners) {
  for (const auto &owner : owners) {
    assert(owner->retaincnt == owner->releasecnt);
  }
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fuzzed_data_provider(data, size);
  ReleaseState release_state{};
  std::vector<std::unique_ptr<BufOwner>> owners;
  ngtcp2_reorder reorder;
  uint64_t cont_offset = 0;

  ngtcp2_reorder_init(&reorder, release_reorder_buf, &release_state,
                      ngtcp2_mem_default());

  while (fuzzed_data_provider.remaining_bytes()) {
    switch (fuzzed_data_provider.ConsumeIntegralInRange<int>(0, 4)) {
    case 0: {
      auto datalen = fuzzed_data_provider.ConsumeIntegralInRange<size_t>(
        0, std::min<size_t>(512, fuzzed_data_provider.remaining_bytes()));
      auto owner = std::make_unique<BufOwner>();
      uint8_t empty = 0;
      ngtcp2_buf buf;
      size_t nwrite;
      int rv;

      owner->data = fuzzed_data_provider.ConsumeBytes<uint8_t>(datalen);

      ngtcp2_buf_init(&buf, owner->data.empty() ? &empty : owner->data.data(),
                      owner->data.size(), NGTCP2_BUF_ORIGIN_APPLICATION,
                      NGTCP2_BUF_DIR_RX, NGTCP2_BUF_PURPOSE_REORDER_RX,
                      owner.get(), retain_buf, release_buf);
      buf.last = buf.end;

      rv = ngtcp2_buf_retain_owner(&buf);
      if (rv != 0) {
        break;
      }

      owners.push_back(std::move(owner));

      rv = ngtcp2_reorder_push(
        &reorder, &buf, fuzzed_data_provider.ConsumeIntegral<uint64_t>(),
        cont_offset, 0, &nwrite);
      if (rv != 0) {
        ngtcp2_buf_release_owner(&buf);
      }

      break;
    }
    case 1:
      cont_offset = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
      ngtcp2_reorder_remove_prefix(&reorder, cont_offset);
      break;
    case 2: {
      const ngtcp2_buf *buf;
      auto offset = fuzzed_data_provider.ConsumeIntegral<uint64_t>();
      auto datalen = ngtcp2_reorder_data_at(&reorder, &buf, offset);

      if (datalen) {
        ngtcp2_reorder_pop(&reorder, offset,
                           fuzzed_data_provider.ConsumeIntegralInRange<size_t>(
                             1, datalen));
      }

      break;
    }
    case 3: {
      const ngtcp2_buf *buf;

      ngtcp2_reorder_data_at(
        &reorder, &buf, fuzzed_data_provider.ConsumeIntegral<uint64_t>());
      break;
    }
    case 4:
      cont_offset = ngtcp2_reorder_first_gap_offset(&reorder, cont_offset);
      break;
    }
  }

  ngtcp2_reorder_free(&reorder);
  check_owners_balanced(owners);

  (void)release_state;

  return 0;
}
